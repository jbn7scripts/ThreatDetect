import os
import joblib

class ModelLoader:
    """
    Handle loading models with their appropriate class mappings and feature orders.
    """
    def __init__(self):
        # Default class mapping
        self.default_class_mapping = {
            0: 'BENIGN',
            1: 'Bot',
            2: 'DDoS',
            3: 'DoS GoldenEye',
            4: 'DoS Hulk',
            5: 'DoS Slowhttptest',
            6: 'DoS slowloris',
            7: 'FTP-Patator',
            8: 'Heartbleed',
            9: 'Infiltration',
            10: 'PortScan',
            11: 'SSH-Patator',
            12: 'Web Attack - Brute Force',
            13: 'Web Attack - SQL Injection',
            14: 'Web Attack - XSS'
        }
        
        # Scapy models class mapping (DDos, Normal, Port Scanning)
        self.scapy_class_mapping = {
            'normal': 'BENIGN',
            'ddos': 'DDoS',
            'portscan': 'PortScan'
        }
        
        # Default feature order
        self.default_feature_order = [
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
        
    def load_model(self, model_name):
        """
        Load a model and return it with appropriate class mapping and feature order.
        
        Args:
            model_name (str): Name of the model file
            
        Returns:
            tuple: (model, class_mapping_reverse, feature_order)
        """
        model_path = os.path.join('models', model_name)
        print(f"Loading model from {model_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}")
        
        # Load the model
        model = joblib.load(model_path)
        
        # Determine which class mapping to use based on the model name
        if model_name.startswith('scapy_'):
            class_mapping = self.scapy_class_mapping
            print(f"Using scapy class mapping for {model_name}")
            scaler = joblib.load(os.path.join('models','normalisation', 'scapy_scaler.pkl'))
            print(f"Scaler loaded from {os.path.join('models', 'scapy_scaler.pkl')}")
        else:
            class_mapping = self.default_class_mapping
            print(f"Using default class mapping for {model_name}")
            scaler = None
        
        # Always use the default feature order
        # If in the future you need different feature orders, you can extend this
        feature_order = self.default_feature_order

        print(f"Model {model} ")
        
        return model, class_mapping, feature_order, scaler