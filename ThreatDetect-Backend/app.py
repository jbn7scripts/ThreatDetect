import os
import pickle
import time
import json
import jwt
import bcrypt
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from os import path

from Database import (
    InsertData,
    read_cred,
    get_sniffed_data,
    get_label_counts,
    insert_sniffed_flow,
    fetch_dashboard_overview
)
from sniffer import Sniffer
from flow_manager import FlowManager
from flask_cors import CORS
from Database import fetch_sniffed_data_overview
from model_loader import ModelLoader

# -------------- Configuration & Globals ----------------
SECRET_KEY = "some_very_secret_key"  # used for JWT encoding
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 2

# Email configuration 
SENDER_EMAIL = "detectthreat@gmail.com"
SENDER_PASSWORD = "evya pafe jbim ceqb"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

model_loader = ModelLoader()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pcap', 'csv'}

# -------------- JWT Helpers ----------------
def create_jwt_token(email):
    """
    Create a JWT token that expires in JWT_EXPIRY_HOURS hours.
    """
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt_token(token):
    """
    Decode a JWT token. Returns None if invalid or expired.
    """
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def jwt_required(f):
    """
    Decorator to protect endpoints that require authentication.
    Expects 'Authorization: Bearer <token>' header.
    """
    from functools import wraps
    from flask import request

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if not auth_header:
            return jsonify({"message": "Missing Authorization header"}), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({"message": "Invalid token header"}), 401

        token = parts[1]
        decoded = decode_jwt_token(token)
        if not decoded:
            return jsonify({"message": "Token is invalid or expired"}), 401

        # You could store user info in request context if needed
        request.user_email = decoded["email"]
        return f(*args, **kwargs)
    return wrapper

# -------------- Email Helper ----------------
def send_email(to_email, subject, body):
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
        print(f"Failed to send email: {str(e)}")


def load_model_with_mappings(model_name):
    """
    Load a model using the ModelLoader which handles different class mappings.
    """
    try:
        model, class_mapping, feature_order, scaler = model_loader.load_model(model_name)
        return model, class_mapping, feature_order, scaler
    except Exception as e:
        print(f"Error loading model {model_name}: {str(e)}")
        return None, {}, [], None

# Load the default model
default_model_name ='scapy_Random_Forest.pkl' #'rf_classifier.pkl'
loaded_model, class_mapping_reverse_default, feature_order_default, scaler = load_model_with_mappings(default_model_name)


# -------------- Background Sniffer Setup ----------------
sniffer_instance = Sniffer(
    bpf_filter="tcp",
    batch_size=40,
    loaded_model=loaded_model,
    scaler=scaler,
    class_mapping_reverse=class_mapping_reverse_default,
    feature_order=feature_order_default,
    send_email_func=send_email,
    admin_email="admin@example.com"
)

def activate_sniffer():
    """
    Start background sniffing in a daemon thread.
    """
    sniffer_instance.start_sniffing()

# -------------- Flask App Factory ----------------
def create_app():
    app = Flask(__name__)
    # If you want to store any config or secret keys for Flask itself
    app.config["SECRET_KEY"] = "flask_secret_key"  # not for JWT, just for any internal usage
    
    with app.app_context():
        activate_sniffer()
    return app

app = create_app()
CORS(app)  

# We store references so the Sniffer can see them.
app.config["LOADED_MODEL"] = loaded_model
app.config["scaler"] = scaler
app.config["LOADED_MODEL_NAME"] = default_model_name
app.config["CLASS_MAPPING_REVERSE"] = class_mapping_reverse_default
app.config["FEATURE_ORDER"] = feature_order_default
app.config["SEND_EMAIL_FUNC"] = send_email
app.config["ADMIN_EMAIL"] = "admin@example.com"


# -------------- User Registration & Login ----------------
@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Register a new user with hashed password. Expects JSON:
    {
      "name": "...",
      "email": "...",
      "password": "..."
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "No JSON body"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not all([name, email, password]):
        return jsonify({"message": "Missing fields"}), 400

    # Hash the password
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_pw_str = hashed_pw.decode('utf-8')

    # Insert the user
    try:
        # InsertData now should store hashed_pw_str
        InsertData(name, email, hashed_pw_str, mobile=0)
        return jsonify({"message": "Registration successful"}), 201
    except Exception as e:
        return jsonify({"message": f"Registration failed: {str(e)}"}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Login user. Expects JSON:
    {
      "email": "...",
      "password": "..."
    }
    Returns JWT token if successful
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "No JSON body"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    # read_cred now returns user row or None
    user_row = read_cred(email)
    if not user_row:
        return jsonify({"message": "User not found"}), 401

    stored_hashed_pw = user_row[2]  # index 2 if the row is (username, email, password, mobile)
    if bcrypt.hashpw(password.encode('utf-8'), stored_hashed_pw.encode('utf-8')).decode('utf-8') == stored_hashed_pw:
        # Password matches
        token = create_jwt_token(email)
        sniffer_instance.set_user_email(email)  # Set user email for alerting
        return jsonify({"token": token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


# -------------- Single-Flow Prediction (Manual) ----------------
@app.route("/api/predict", methods=["POST"])
@jwt_required
def api_predict():
    """
    Single-flow feature submission in JSON form. Example request JSON:
    {
      " Fwd Packet Length Mean": 123.0,
      " Fwd Packet Length Max": 456.0,
      ...
    }
    Returns the predicted class.
    """
    try:
        req_data = request.get_json()
        if not req_data:
            return jsonify({"error": "No JSON body"}), 400

        user_input = {}
        for col in app.config["FEATURE_ORDER"]:
            val = req_data.get(col, 0.0)
            try:
                user_input[col] = float(val)
            except ValueError:
                user_input[col] = 0.0

        df = pd.DataFrame([user_input])
        df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
        df = df[app.config["FEATURE_ORDER"]]

        model = app.config["LOADED_MODEL"]
        if not model:
            return jsonify({"error": "No model loaded"}), 500
        
        if scaler:
            # Scale the features if a scaler is provided
            df = scaler.transform(df)

        # Handle prediction more carefully
        prediction = model.predict(df)
        pred = prediction[0]
        
        # Handle both scalar and array-like predictions
        if hasattr(pred, '__len__') and not isinstance(pred, str):
            # If pred is array-like, take the first element
            pred = pred[0]
        
        # Convert to int if possible for dictionary lookup
        try:
            pred = int(pred)
        except (ValueError, TypeError):
            # If conversion fails, keep the original value
            pass
            
        decoded_class = app.config["CLASS_MAPPING_REVERSE"].get(pred, 'Unknown')

        # Optionally email the user
        # request.user_email is set from the JWT token
        user_email = request.user_email
        subject = "Prediction Results"
        body = f"Hello,\n\nYour predicted class is: {decoded_class}.\n\nRegards,\nThreat Detect Team"
        send_email(user_email, subject, body)

        return jsonify({"prediction": decoded_class}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------- Batch Classification: CSV or PCAP ----------------
@app.route("/api/upload", methods=["POST"])
@jwt_required
def api_upload():
    """
    Expects a file in form-data (key='file'). Supports CSV or PCAP.
    Returns predictions as JSON.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    extension = filename.rsplit('.', 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type: {extension}"}), 400

    model = app.config["LOADED_MODEL"]
    if not model:
        return jsonify({"error": "No model loaded."}), 500

    try:
        if extension == 'csv':
            df = pd.read_csv(file)
            df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)

            missing_cols = [
                c for c in app.config["FEATURE_ORDER"] if c not in df.columns
            ]
            if missing_cols:
                return jsonify({"error": f"CSV missing columns: {missing_cols}"}), 400

            df = df[app.config["FEATURE_ORDER"]]
            if scaler:
                # Scale the features if a scaler is provided
                df = scaler.transform(df)

            predictions = model.predict(df)
            probas = model.predict_proba(df)
            class_names = [
                app.config["CLASS_MAPPING_REVERSE"].get(p, 'Unknown')
                for p in predictions
            ]
            response_data = []
            for i, (pred_label, proba) in enumerate(zip(predictions, probas)):
                response_data.append({
                    'sr_no': i + 1,
                    'class_name': class_names[i],
                    'probability': float(proba.max())
                })

            

            return jsonify({"predictions": response_data}), 200

        elif extension == 'pcap':
            # Save to disk
            save_path = os.path.join('uploads', filename)
            file.save(save_path)

            # parse pcap
            flow_manager = FlowManager()
            flows_dict = flow_manager.parse_pcap_file(save_path)

            results = []
            idx = 1
            for key, flow_stats in flows_dict.items():
                feats = flow_stats.compute_features()
                df = pd.DataFrame([feats])
                df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
                df = df[app.config["FEATURE_ORDER"]]
                if scaler:
                    # Scale the features if a scaler is provided
                    df = scaler.transform(df)

                pred = model.predict(df)[0]
                attack_name = app.config["CLASS_MAPPING_REVERSE"].get(pred, 'Unknown')

                # Insert into DB
                insert_sniffed_flow(
                    flow_key=str(key),
                    features=feats,
                    prediction_label=attack_name,
                    timestamp=time.time()
                )

                results.append({
                    'sr_no': idx,
                    'flow_key': str(key),
                    'class_name': attack_name
                })
                idx += 1

            return jsonify({"predictions": results}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------- Real-Time Sniffed Data & Chart ----------------
@app.route("/api/sniffed_data", methods=["GET"])
@jwt_required
def api_sniffed_data():
    """
    Return sniffed flow data from DB as JSON.
    """
    data = get_sniffed_data()
    return jsonify({"data": data}), 200

@app.route("/api/chart_data", methods=["GET"])
@jwt_required
def api_chart_data():
    """
    Return label counts { label: count } for e.g. a pie chart.
    """
    label_counts = get_label_counts()
    return jsonify({"label_counts": label_counts}), 200


# -------------- Model Management ----------------
@app.route("/api/change_model", methods=["POST"])
@jwt_required
def api_change_model():
    """
    Hot-swap the model. Expects JSON: { "model_name": "<some.pkl>" }
    Now handles different model types and their class mappings.
    """
    req_data = request.get_json()
    if not req_data or "model_name" not in req_data:
        return jsonify({"error": "model_name not provided"}), 400

    model_name = req_data["model_name"]
    
    try:
        # Use the ModelLoader to get the model and proper class mapping
        model, class_mapping, feature_order, scaler = load_model_with_mappings(model_name)
        
        if model is None:
            return jsonify({"error": f"Failed to load model: {model_name}"}), 500
        
        # Update app config
        app.config["LOADED_MODEL"] = model
        app.config["LOADED_MODEL_NAME"] = model_name
        app.config["CLASS_MAPPING_REVERSE"] = class_mapping
        app.config["FEATURE_ORDER"] = feature_order
        app.config["scaler"] = scaler
        
        # Update the sniffer's model and mappings
        sniffer_instance.loaded_model = model
        sniffer_instance.class_mapping_reverse = class_mapping
        sniffer_instance.feature_order = feature_order
        
        return jsonify({
            "message": f"Model changed successfully to {model_name}",
            "class_mapping": class_mapping
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/list_models", methods=["GET"])
@jwt_required
def api_list_models():
    """
    List available models in the 'models' directory.
    """
    models_dir = "models"
    files = os.listdir(models_dir) if os.path.exists(models_dir) else []
    models = [f for f in files if f.endswith('.pkl')]
    return jsonify({"available_models": models}), 200

@app.route("/api/current_model", methods=["GET"])
@jwt_required
def api_current_model():
    """
    Return the currently loaded model name.
    """
    current_model = app.config["LOADED_MODEL_NAME"]
    if current_model:
        return jsonify({"current_model": current_model}), 200
    else:
        return jsonify({"error": "No model loaded"}), 404


# -------------- Root or Default --------------
@app.route("/", methods=["GET"])
def api_root():
    """
    Simple root endpoint to confirm API is online.
    """
    return jsonify({"message": "ThreatDetect REST API is running"}), 200

@app.route("/api/overview_records", methods=["GET"])
@jwt_required
def api_overview_records():
    try:
        data = fetch_dashboard_overview()
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------- Main Entry Point -------------
if __name__ == "__main__":
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(host="0.0.0.0", port=5000, debug=False)
