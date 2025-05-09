# import threading
# import time
# from scapy.all import sniff
# from flow_manager import FlowManager
# from Database import insert_sniffed_flow
# import pandas as pd
# import numpy as np

# class Sniffer:
#     def __init__(self, 
#                  bpf_filter="tcp", 
#                  batch_size=40,
#                  loaded_model=None,
#                  class_mapping_reverse=None,
#                  feature_order=None,
#                  send_email_func=None,
#                  admin_email="admin@example.com"):
#         self.bpf_filter = bpf_filter
#         self.flow_manager = FlowManager()
#         self.sniff_thread = None
#         self.packet_count = 0
#         self.batch_size = batch_size

#         # Store references so we don't need current_app
#         self.loaded_model = loaded_model
#         self.class_mapping_reverse = class_mapping_reverse or {}
#         self.feature_order = feature_order or []
#         self.send_email_func = send_email_func
#         self.admin_email = admin_email  # used if we want to email an admin

#     def _packet_handler(self, packet):
#         #print(packet.summary())
#         self.flow_manager.process_packet(packet)
#         self.packet_count += 1

#         if self.packet_count >= self.batch_size:
#             self.handle_batch_prediction()

#     def handle_batch_prediction(self):
#         if not self.loaded_model:
#             print("[Sniffer] No model loaded. Skipping prediction.")
#             self.reset_flows()
#             return

#         flows_dict = self.flow_manager.flows
#         for key, flow_stats in flows_dict.items():
#             feats = flow_stats.compute_features()

#             df = pd.DataFrame([feats])
#             df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
#             df = df[self.feature_order] 

#             pred = self.loaded_model.predict(df.values)[0]
#             attack_name = self.class_mapping_reverse.get(pred, 'Unknown')

#             # Insert into DB
#             insert_sniffed_flow(
#                 flow_key=str(key),
#                 features=feats,
#                 prediction_label=attack_name,
#                 timestamp=time.time()
#             )

#         self.reset_flows()

#     def reset_flows(self):
#         self.flow_manager = FlowManager()
#         self.packet_count = 0

#     def send_malicious_email(self, flow_key, attack_name):
#         subject = "Malicious Traffic Detected"
#         body = f"A malicious flow has been detected:\nFlow Key: {flow_key}\nPrediction: {attack_name}"
#         try:
#             # If we want to send to a single admin address:
#             self.send_email_func(self.admin_email, subject, body)
#         except Exception as e:
#             print(f"Failed to send malicious email: {str(e)}")

#     def _sniff_loop(self):
#         sniff(
#             filter=self.bpf_filter,
#             prn=self._packet_handler,
#             store=False
#         )

#     def start_sniffing(self):
#         if self.sniff_thread and self.sniff_thread.is_alive():
#             return
#         self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
#         self.sniff_thread.start()
#         print("[Sniffer] Started background sniffing...")

#     def stop_sniffing(self):
#         print("[Sniffer] Stop sniffing requested (not trivial).")
import threading
import time
from scapy.all import sniff
from flow_manager import FlowManager
from Database import insert_sniffed_flow
import pandas as pd
import numpy as np

class Sniffer:
    def __init__(self, 
                 bpf_filter="tcp", 
                 batch_size=40,
                 loaded_model=None,
                 scaler=None,
                 class_mapping_reverse=None,
                 feature_order=None,
                 send_email_func=None,
                 admin_email="admin@example.com"):
        self.bpf_filter = bpf_filter
        self.flow_manager = FlowManager()
        self.sniff_thread = None
        self.packet_count = 0
        self.batch_size = batch_size

        # Store references so we don't need current_app
        self.loaded_model = loaded_model
        self.scaler = scaler  # Added scaler reference
        self.class_mapping_reverse = class_mapping_reverse or {}
        self.feature_order = feature_order or []
        self.send_email_func = send_email_func
        self.admin_email = admin_email  # used if we want to email an admin
        self.consecutive_malicious_count = 0
        self.user_email = None
        self.alert_sent_for_streak = False  # Add this flag

    def _packet_handler(self, packet):
        #print(packet.summary())
        self.flow_manager.process_packet(packet)
        self.packet_count += 1

        if self.packet_count >= self.batch_size:
            self.handle_batch_prediction()

    def handle_batch_prediction(self):
        if not self.loaded_model:
            print("[Sniffer] No model loaded. Skipping prediction.")
            self.reset_flows()
            return

        flows_dict = self.flow_manager.flows
        for key, flow_stats in flows_dict.items():
            feats = flow_stats.compute_features()

            df = pd.DataFrame([feats])
            df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
            df = df[self.feature_order]

            if self.scaler:
                df = self.scaler.transform(df)

            
            prediction = self.loaded_model.predict(df)
            # Extract the scalar value from prediction array
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
                
            attack_name = self.class_mapping_reverse.get(pred, 'Unknown')

            # Insert into DB
            insert_sniffed_flow(
                flow_key=str(key),
                features=feats,
                prediction_label=attack_name,
                timestamp=time.time()
            )

            # Improved alert logic: only send once per malicious streak
            if attack_name != "BENIGN":
                self.consecutive_malicious_count += 1
                if (self.consecutive_malicious_count == 3 and not self.alert_sent_for_streak and self.user_email):
                    subject = "ThreatDetect: 3 Consecutive Malicious Packets Detected"
                    body = f"Three consecutive malicious packets have been detected.\nLast flow: {key}\nPrediction: {attack_name}"
                    self.send_email_func(self.user_email, subject, body)
                    self.alert_sent_for_streak = True  # Only send once per streak
            else:
                self.consecutive_malicious_count = 0
                self.alert_sent_for_streak = False  # Reset on benign

        self.reset_flows()

    def reset_flows(self):
        self.flow_manager = FlowManager()
        self.packet_count = 0

    def send_malicious_email(self, flow_key, attack_name):
        subject = "Malicious Traffic Detected"
        body = f"A malicious flow has been detected:\nFlow Key: {flow_key}\nPrediction: {attack_name}"
        try:
            # If we want to send to a single admin address:
            self.send_email_func(self.admin_email, subject, body)
        except Exception as e:
            print(f"Failed to send malicious email: {str(e)}")

    def _sniff_loop(self):
        try:
            sniff(
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False
            )
        except Exception as e:
            print(f"[Sniffer] Error in sniffing loop: {str(e)}")
            # Restart sniffing after a short delay
            time.sleep(5)
            print("[Sniffer] Attempting to restart sniffing...")
            self._sniff_loop()

    def start_sniffing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        print("[Sniffer] Started background sniffing...")

    def stop_sniffing(self):
        print("[Sniffer] Stop sniffing requested (not trivial).")

    def set_user_email(self, email):
        self.user_email = email