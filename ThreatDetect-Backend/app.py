# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Jaber Ali Farooqi · W1926781 · University of Westminster                ║
# ║  Final-Year Project – ThreatDetect (Real-Time Network Threat Detection)  ║
# ║  © 2025                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
ThreatDetect REST API
=====================

A Flask-based back-end that does four main jobs:

1. **User management** – registration, login, JWT creation/validation.
2. **Threat detection** – single-flow predictions and batch classification
   (CSV / PCAP) using a Scikit-Learn model.
3. **Real-time sniffing** – background thread with scapy sniffing packets,
   predicting attacks, and optionally e-mailing alerts.
4. **Model lifecycle** – hot-swapping between different `.pkl` models at
   runtime, plus listing the ones available.

Key design choices
------------------
* **Thread safety** – the background `Sniffer` runs as a daemon and uses
  references stored in `app.config` so it always has the currently-loaded
  model and mapping.
* **Security** – JWT protects the majority of endpoints; bcrypt hashes
  passwords before persisting; e-mail / secret keys should **really** be
  moved to environment variables or a secret vault in production.
* **Extensibility** – `ModelLoader` abstracts away model-specific feature
  ordering, scaler, and class-mapping details, so you can drop in new
  models without touching endpoint logic.
"""

# ---------------------------------------------------------------------------
# Standard library imports
# ---------------------------------------------------------------------------
import os
import time
import json
import pickle  # (Used elsewhere outside this snippet)
from datetime import datetime, timedelta
from os import path

# ---------------------------------------------------------------------------
# Third-party imports
# ---------------------------------------------------------------------------
import jwt                     # → JSON Web Tokens
import bcrypt                  # → Password hashing
import numpy as np             # → Numerical ops
import pandas as pd            # → Dataframes
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS    # → Cross-origin resource sharing

# ---------------------------------------------------------------------------
# Local / project imports
# ---------------------------------------------------------------------------
from Database import (
    InsertData,
    read_cred,
    get_sniffed_data,
    get_label_counts,
    insert_sniffed_flow,
    fetch_sniffed_data_overview
)
from sniffer import Sniffer
from flow_manager import FlowManager
from model_loader import ModelLoader

# ---------------------------------------------------------------------------
# Configuration & “global” singletons
# ---------------------------------------------------------------------------
SECRET_KEY        = "some_very_secret_key"   # JWT signing key    (→ env var!)
JWT_ALGORITHM     = "HS256"
JWT_EXPIRY_HOURS  = 2

# --- SMTP (demo values – move to env vars in production) --------------------
SENDER_EMAIL      = "gainheretech@gmail.com"
SENDER_PASSWORD   = "vqqt jaeg jkkl zusf"
SMTP_SERVER       = "smtp.gmail.com"
SMTP_PORT         = 587

# Instantiate helper that loads pickled models + metadata --------------------
model_loader = ModelLoader()

# File extensions we allow in `/api/upload`
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pcap', 'csv'}

# =============================================================================
# JWT utilities
# =============================================================================
def create_jwt_token(email: str) -> str:
    """
    Return a signed JWT that encodes the user’s e-mail and an expiry timestamp.
    """
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict | None:
    """
    Decode a JWT and return its payload **or** None if invalid / expired.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def jwt_required(f):
    """
    Decorator for protecting Flask routes with JWT (“Bearer <token>” header).
    Attaches `request.user_email` for downstream use.
    """
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"message": "Missing Authorization header"}), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({"message": "Invalid token header"}), 401

        decoded = decode_jwt_token(parts[1])
        if not decoded:
            return jsonify({"message": "Token is invalid or expired"}), 401

        request.user_email = decoded["email"]      # ← expose in view
        return f(*args, **kwargs)

    return wrapper

# =============================================================================
# Outbound e-mail helper
# =============================================================================
def send_email(to_email: str, subject: str, body: str) -> None:
    """
    Send a plain-text e-mail via SMTP. Prints a log line on success/failure.

    NOTE: In production you’d wrap this in retries / async queue.
    """
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    try:
        message = MIMEMultipart()
        message["From"] = SENDER_EMAIL
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(message)

        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

# =============================================================================
# Model loading convenience (wraps ModelLoader for error handling)
# =============================================================================
def load_model_with_mappings(model_name: str):
    """
    Wrapper around `ModelLoader.load_model`.

    Returns (model, class_mapping, feature_order, scaler) **or**
    (None, {}, [], None) on failure (keeps API endpoints resilient).
    """
    try:
        return model_loader.load_model(model_name)
    except Exception as e:
        print(f"Error loading model {model_name}: {e}")
        return None, {}, [], None

# -------------------------------- Default model bootstrapping --------------
default_model_name = 'scapy_Random_Forest.pkl'  # → could be overridden later

loaded_model, class_mapping_reverse_default, feature_order_default, scaler = \
    load_model_with_mappings(default_model_name)

# =============================================================================
# Packet sniffer – runs in its own daemon thread
# =============================================================================
sniffer_instance = Sniffer(
    bpf_filter="tcp",                 # capture only TCP packets
    batch_size=40,
    loaded_model=loaded_model,
    scaler=scaler,
    class_mapping_reverse=class_mapping_reverse_default,
    feature_order=feature_order_default,
    send_email_func=send_email,       # dependency-injected for testability
    admin_email="admin@example.com"
)

def activate_sniffer() -> None:
    """Kick off background sniffing (non-blocking)."""
    sniffer_instance.start_sniffing()

# =============================================================================
# Flask application factory
# =============================================================================
def create_app() -> Flask:
    """
    Build and configure the Flask app, then start the background sniffer.

    `app.config` is used as a *shared registry* between routes and the
    sniffer thread for the current model, scaler, etc.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "flask_secret_key"    # (not the JWT key!)

    with app.app_context():
        activate_sniffer()

    return app

app = create_app()
CORS(app)  # Allow all origins – tighten this in production

# Store singletons in app.config so every part of the app sees the same refs
app.config.update({
    "LOADED_MODEL":           loaded_model,
    "scaler":                 scaler,
    "LOADED_MODEL_NAME":      default_model_name,
    "CLASS_MAPPING_REVERSE":  class_mapping_reverse_default,
    "FEATURE_ORDER":          feature_order_default,
    "SEND_EMAIL_FUNC":        send_email,
    "ADMIN_EMAIL":            "admin@example.com"
})

# =============================================================================
# ---------------------------  AUTH & USERS  ----------------------------------
# =============================================================================
@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Register a brand-new user.

    Expected JSON body
    ------------------
    {
      "name":     "<str>",
      "email":    "<str>",
      "password": "<str>"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "No JSON body"}), 400

    name, email, password = data.get("name"), data.get("email"), data.get("password")
    if not all([name, email, password]):
        return jsonify({"message": "Missing fields"}), 400

    # bcrypt - generate salted hash
    hashed_pw_str = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        InsertData(name, email, hashed_pw_str, mobile=0)   # ← DB helper
        return jsonify({"message": "Registration successful"}), 201
    except Exception as e:
        return jsonify({"message": f"Registration failed: {e}"}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Authenticate user and return JWT.

    Expected JSON body
    ------------------
    {
      "email":    "<str>",
      "password": "<str>"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "No JSON body"}), 400

    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    user_row = read_cred(email)
    if not user_row:
        return jsonify({"message": "User not found"}), 401

    stored_hash = user_row[2]            # row = (name, email, pw_hash, mobile)
    # bcrypt.hashpw returns _bytes_; decode for comparison with stored str
    if bcrypt.hashpw(password.encode(), stored_hash.encode()).decode() == stored_hash:
        token = create_jwt_token(email)
        return jsonify({"token": token}), 200

    return jsonify({"message": "Invalid credentials"}), 401

# =============================================================================
# ---------------------------  SINGLE FLOW PREDICT  ---------------------------
# =============================================================================
@app.route("/api/predict", methods=["POST"])
@jwt_required
def api_predict():
    """
    Predict the attack type for **one** flow.

    Request: JSON where keys are *exactly* the column names in FEATURE_ORDER.
    Response: { "prediction": "<class_name>" }
    """
    try:
        req_data = request.get_json()
        if not req_data:
            return jsonify({"error": "No JSON body"}), 400

        # Build a single-row dataframe with ALL required columns -----------
        user_input = {}
        for col in app.config["FEATURE_ORDER"]:
            val = req_data.get(col, 0.0)
            try:
                user_input[col] = float(val)
            except ValueError:
                user_input[col] = 0.0

        df = pd.DataFrame([user_input]).replace([np.inf, -np.inf, np.nan], 0.0)
        df = df[app.config["FEATURE_ORDER"]]   # enforce correct order

        model = app.config["LOADED_MODEL"]
        if not model:
            return jsonify({"error": "No model loaded"}), 500

        if scaler:
            df = scaler.transform(df)

        # ------------------------------------------------------------------
        prediction = model.predict(df)
        pred = prediction[0]

        # Convert numpy/int64 etc. to plain int for mapping lookup
        try:
            pred = int(pred)
        except (ValueError, TypeError):
            pass

        decoded_class = app.config["CLASS_MAPPING_REVERSE"].get(pred, 'Unknown')

        # Optional e-mail notification to the same user that made the call
        send_email(
            to_email=request.user_email,
            subject="Prediction Results",
            body=f"Hello,\n\nYour predicted class is: {decoded_class}.\n\nRegards,\nThreat Detect Team"
        )

        return jsonify({"prediction": decoded_class}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# ---------------------------  BATCH UPLOAD  ----------------------------------
# =============================================================================
@app.route("/api/upload", methods=["POST"])
@jwt_required
def api_upload():
    """
    Upload CSV **or** PCAP → returns per-row or per-flow predictions.

    * CSV: must contain all columns specified by `FEATURE_ORDER`.
    * PCAP: parsed into flows by FlowManager; each flow is predicted separately.

    Response schema differs slightly between CSV and PCAP but always lives
    inside `{ "predictions": [...] }`.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename   = secure_filename(file.filename)
    extension  = filename.rsplit('.', 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type: {extension}"}), 400

    model = app.config["LOADED_MODEL"]
    if not model:
        return jsonify({"error": "No model loaded."}), 500

    # ----------------------------- CSV branch -----------------------------
    try:
        if extension == 'csv':
            df = pd.read_csv(file).replace([np.inf, -np.inf, np.nan], 0.0)

            # Ensure every expected column exists
            missing = [c for c in app.config["FEATURE_ORDER"] if c not in df.columns]
            if missing:
                return jsonify({"error": f"CSV missing columns: {missing}"}), 400

            df = df[app.config["FEATURE_ORDER"]]
            if scaler:
                df = scaler.transform(df)

            predictions = model.predict(df)
            probas      = model.predict_proba(df)

            response_data = []
            for i, (pred_label, proba_row) in enumerate(zip(predictions, probas), start=1):
                response_data.append({
                    "sr_no":       i,
                    "class_name":  app.config["CLASS_MAPPING_REVERSE"].get(int(pred_label), 'Unknown'),
                    "probability": float(proba_row.max())
                })

            return jsonify({"predictions": response_data}), 200

        # ---------------------------- PCAP branch -------------------------
        elif extension == 'pcap':
            # Persist file temporarily – FlowManager expects a path
            if not os.path.exists('uploads'):
                os.makedirs('uploads')
            save_path = os.path.join('uploads', filename)
            file.save(save_path)

            flow_manager = FlowManager()
            flows_dict   = flow_manager.parse_pcap_file(save_path)

            results = []
            for idx, (key, flow_stats) in enumerate(flows_dict.items(), start=1):
                feats = flow_stats.compute_features()
                df = pd.DataFrame([feats]).replace([np.inf, -np.inf, np.nan], 0.0)
                df = df[app.config["FEATURE_ORDER"]]
                if scaler:
                    df = scaler.transform(df)

                pred        = int(model.predict(df)[0])
                attack_name = app.config["CLASS_MAPPING_REVERSE"].get(pred, 'Unknown')

                # Log flow prediction to DB for later dashboards
                insert_sniffed_flow(
                    flow_key=str(key),
                    features=feats,
                    prediction_label=attack_name,
                    timestamp=time.time()
                )

                results.append({
                    "sr_no":     idx,
                    "flow_key":  str(key),
                    "class_name": attack_name
                })

            return jsonify({"predictions": results}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# ---------------------------  REAL-TIME DASHBOARDS  --------------------------
# =============================================================================
@app.route("/api/sniffed_data", methods=["GET"])
@jwt_required
def api_sniffed_data():
    """Return every sniffed flow stored in DB."""
    return jsonify({"data": get_sniffed_data()}), 200


@app.route("/api/chart_data", methods=["GET"])
@jwt_required
def api_chart_data():
    """Return a histogram-like dict → `{label: count}` for quick charts."""
    return jsonify({"label_counts": get_label_counts()}), 200

# =============================================================================
# ---------------------------  MODEL MANAGEMENT  ------------------------------
# =============================================================================
@app.route("/api/change_model", methods=["POST"])
@jwt_required
def api_change_model():
    """
    Hot-swap the live model (and scaler / class mapping) without rebooting.

    Expected JSON: { "model_name": "<filename>.pkl" }
    """
    req_data = request.get_json()
    if not req_data or "model_name" not in req_data:
        return jsonify({"error": "model_name not provided"}), 400

    model_name = req_data["model_name"]
    try:
        model, mapping, feature_order, new_scaler = load_model_with_mappings(model_name)
        if model is None:
            return jsonify({"error": f"Failed to load model: {model_name}"}), 500

        # ---------------------- Update global state ----------------------
        app.config.update({
            "LOADED_MODEL":          model,
            "LOADED_MODEL_NAME":     model_name,
            "CLASS_MAPPING_REVERSE": mapping,
            "FEATURE_ORDER":         feature_order,
            "scaler":                new_scaler
        })

        # Let the background sniffer know about the change
        sniffer_instance.loaded_model          = model
        sniffer_instance.class_mapping_reverse = mapping
        sniffer_instance.feature_order         = feature_order

        return jsonify({
            "message":       f"Model changed successfully to {model_name}",
            "class_mapping": mapping
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/list_models", methods=["GET"])
@jwt_required
def api_list_models():
    """Return an array of `.pkl` filenames found under ./models."""
    models_dir = "models"
    files      = os.listdir(models_dir) if os.path.exists(models_dir) else []
    return jsonify({"available_models": [f for f in files if f.endswith('.pkl')]}), 200


@app.route("/api/current_model", methods=["GET"])
@jwt_required
def api_current_model():
    """Return the filename of the model currently in memory."""
    current = app.config["LOADED_MODEL_NAME"]
    return jsonify({"current_model": current}) if current \
        else (jsonify({"error": "No model loaded"}), 404)

# =============================================================================
# ---------------------------  DASHBOARD OVERVIEW  ----------------------------
# =============================================================================
@app.route("/api/overview_records", methods=["GET"])
@jwt_required
def api_overview_records():
    """Lightweight endpoint for data-table views – keeps amount small."""
    try:
        return jsonify(fetch_sniffed_data_overview()), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# ---------------------------  ROOT HEALTH CHECK  -----------------------------
# =============================================================================
@app.route("/", methods=["GET"])
def api_root():
    """Basic liveness probe → returns 200 OK with static message."""
    return jsonify({"message": "ThreatDetect REST API is running"}), 200

# =============================================================================
# ---------------------------  APP ENTRY-POINT  -------------------------------
# =============================================================================
if __name__ == "__main__":
    # Ensure ./uploads exists before first PCAP upload
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    # Changed to the correct call below.
    app.run(host="0.0.0.0", port=5000, debug=False)
