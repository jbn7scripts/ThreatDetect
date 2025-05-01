# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Jaber Ali Farooqi · W1926781 · University of Westminster                ║
# ║  Final-Year Project – ThreatDetect (Real-Time Network Threat Detection)  ║
# ║  © 2025                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
ModelLoader – dynamic model + metadata bootstrapper
===================================================

The rest-API needs four artefacts at run-time:

1. **model** - the pickled `sklearn` estimator (`joblib.dump` format)  
2. **class_mapping_reverse** - maps model output → human label  
3. **feature_order** - ordered list of 20 column names the model expects  
4. **scaler** (optional) - `StandardScaler` or similar to pre-transform
   features before `.predict()` (only some models need one)

`ModelLoader` centralises the logic so endpoints don’t care which flavour
is being loaded (“scapy_…”, full CIC-IDS, etc.).

Extending later
---------------
* Add a new model prefix → new branch in `load_model` with its own
  mapping / scaler path.
* If a model has a **different feature order**, add an attribute
  `self.<prefix>_feature_order` and select accordingly.

Security / reliability
----------------------
* The actual pickles live under `./models/`; loading untrusted pickle
  files is dangerous. Keep that folder write-protected in production.
"""

# ---------------------------------------------------------------------------  
# Standard-library imports  
# ---------------------------------------------------------------------------
import os
from typing import Tuple, Dict, List, Any

# ---------------------------------------------------------------------------  
# Third-party imports  
# ---------------------------------------------------------------------------
import joblib


# =============================================================================
# ------------------------------  MODEL LOADER  -------------------------------
# =============================================================================
class ModelLoader:
    """
    Lightweight helper that returns `(model, mapping, feature_order, scaler)`.

    Attributes
    ----------
    default_class_mapping : dict[int, str]
        15-class CIC-IDS target names (Random-Forest default).
    scapy_class_mapping : dict[str, str]
        Three-class mapping for the “scapy_…” DDoS/PortScan demo model.
    default_feature_order : list[str]
        Canonical 20-feature column order (used by *all* current models).
    """

    # ---------------------------------------------------------------------  
    def __init__(self) -> None:
        # -------- 15-class CIC-IDS reverse mapping ----------------------
        self.default_class_mapping: Dict[int, str] = {
            0:  'BENIGN',
            1:  'Bot',
            2:  'DDoS',
            3:  'DoS GoldenEye',
            4:  'DoS Hulk',
            5:  'DoS Slowhttptest',
            6:  'DoS slowloris',
            7:  'FTP-Patator',
            8:  'Heartbleed',
            9:  'Infiltration',
            10: 'PortScan',
            11: 'SSH-Patator',
            12: 'Web Attack - Brute Force',
            13: 'Web Attack - SQL Injection',
            14: 'Web Attack - XSS'
        }

        # -------- 3-class demo mapping for scapy live-capture model -----
        self.scapy_class_mapping: Dict[str, str] = {
            'normal':   'BENIGN',
            'ddos':     'DDoS',
            'portscan': 'PortScan'
        }

        # -------- Uniform 20-feature order (CIC-FlowMeter subset) -------
        self.default_feature_order: List[str] = [
            ' Fwd Packet Length Mean',
            ' Fwd Packet Length Max',
            ' Avg Fwd Segment Size',
            ' Subflow Fwd Bytes',
            'Total Length of Fwd Packets',
            ' Flow IAT Max',
            ' Average Packet Size',
            ' Bwd Packet Length Std',
            ' Flow Duration',
            ' Avg Bwd Segment Size',
            ' Bwd Packets/s',
            ' Packet Length Mean',
            'Init_Win_bytes_forward',
            ' Init_Win_bytes_backward',
            ' Packet Length Std',
            ' Fwd IAT Max',
            ' Fwd Packet Length Std',
            ' Packet Length Variance',
            ' Total Length of Bwd Packets',
            ' Flow Packets/s'
        ]

    # ---------------------------------------------------------------------  
    def load_model(self, model_name: str) -> Tuple[Any, Dict, List[str], Any | None]:
        """
        Load a pickle from `./models/` and return its companion metadata.

        Parameters
        ----------
        model_name : str
            Filename (e.g. `"scapy_Random_Forest.pkl"`).

        Returns
        -------
        tuple
            `(model, class_mapping_reverse, feature_order, scaler)`
            * `scaler` is `None` if the model was trained without one.
        """
        model_path = os.path.join('models', model_name)
        print(f"[ModelLoader] Loading model from {model_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}")

        # ------------- un-pickle model ----------------------------------
        model = joblib.load(model_path)

        # ------------- choose mapping + optional scaler -----------------
        if model_name.startswith('scapy_'):
            class_mapping = self.scapy_class_mapping
            print(f"[ModelLoader] Using *scapy* class mapping for {model_name}")

            scaler_path = os.path.join('models', 'normalisation', 'scapy_scaler.pkl')
            scaler      = joblib.load(scaler_path)
            print(f"[ModelLoader] Scaler loaded from {scaler_path}")
        else:
            class_mapping = self.default_class_mapping
            scaler        = None
            print(f"[ModelLoader] Using *default* class mapping for {model_name}")

        # ------------- currently all models share the same feature order
        feature_order = self.default_feature_order

        print(f"[ModelLoader] Model object: {model}")
        return model, class_mapping, feature_order, scaler
