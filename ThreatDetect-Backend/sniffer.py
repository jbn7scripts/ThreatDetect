# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Jaber Ali Farooqi · W1926781 · University of Westminster                ║
# ║  Final-Year Project – ThreatDetect (Real-Time Network Threat Detection)  ║
# ║  © 2025                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
sniffer.py – background packet capture & batch prediction
=========================================================

Spawns a **daemon** thread that runs Scapy’s `sniff()` loop.  
Every `batch_size` packets are aggregated into flows, converted to the
20-feature vector, pushed through the currently-loaded ML model, and
stored in the `sniffed_data` table.

Key points
----------
* **Scaler-aware** – if `scaler` is provided, features are normalised
  before prediction.
* **Crash-resilient** – any exception in Scapy’s loop sleeps 5 s and
  restarts automatically.
* **Thread-safe singletons** – `loaded_model`, `class_mapping_reverse`,
  etc. are injected so we don’t rely on Flask’s `current_app`.
"""

# ---------------------------------------------------------------------------  
# Standard-library imports  
# ---------------------------------------------------------------------------
import threading
import time
from typing import Callable, Any

# ---------------------------------------------------------------------------  
# Third-party imports  
# ---------------------------------------------------------------------------
from scapy.all import sniff
import pandas as pd
import numpy as np

# ---------------------------------------------------------------------------  
# Local imports  
# ---------------------------------------------------------------------------
from flow_manager import FlowManager
from Database import insert_sniffed_flow


# =============================================================================
# ------------------------------  SNIFFER CLASS  ------------------------------
# =============================================================================
class Sniffer:
    """
    Background packet sniffer.

    Parameters
    ----------
    bpf_filter : str
        BPF expression passed to Scapy (default ``"tcp"``).
    batch_size : int
        Run a prediction batch after this many packets.
    loaded_model : sklearn-like estimator | None
        Current ML model (must implement ``predict``).
    scaler : sklearn transformer | None
        Optional normaliser applied before predicting.
    class_mapping_reverse : dict[int|str, str]
        Converts model output → human-readable label.
    feature_order : list[str]
        Column order expected by the model.
    send_email_func : Callable[[str, str, str], None] | None
        Injected so it can be mocked in tests.
    admin_email : str
        Destination for alert e-mails (not used in API right now).
    """

    # -----------------------------------------------------------------
    def __init__(
        self,
        bpf_filter: str = "tcp",
        batch_size: int = 40,
        loaded_model: Any | None = None,
        scaler: Any | None = None,
        class_mapping_reverse: dict | None = None,
        feature_order: list[str] | None = None,
        send_email_func: Callable[[str, str, str], None] | None = None,
        admin_email: str = "admin@example.com",
    ) -> None:
        self.bpf_filter = bpf_filter
        self.batch_size = batch_size

        # Flow aggregation
        self.flow_manager = FlowManager()
        self.packet_count = 0

        # Daemon thread handle
        self.sniff_thread: threading.Thread | None = None

        # Injected singletons
        self.loaded_model = loaded_model
        self.scaler = scaler
        self.class_mapping_reverse = class_mapping_reverse or {}
        self.feature_order = feature_order or []
        self.send_email_func = send_email_func
        self.admin_email = admin_email

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------
    def _packet_handler(self, packet) -> None:
        """Scapy callback for each captured packet."""
        self.flow_manager.process_packet(packet)
        self.packet_count += 1

        if self.packet_count >= self.batch_size:
            self._handle_batch_prediction()

    def _handle_batch_prediction(self) -> None:
        """Predict a label for every active flow and persist to DB."""
        if not self.loaded_model:
            print("[Sniffer] No model loaded – skipping batch.")
            self._reset_flows()
            return

        for key, flow_stats in self.flow_manager.flows.items():
            feats = flow_stats.compute_features()

            df = pd.DataFrame([feats])
            df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
            df = df[self.feature_order]

            if self.scaler is not None:
                df = self.scaler.transform(df)

            prediction = self.loaded_model.predict(df)
            pred = prediction[0]

            # Flatten numpy array / dtype
            if hasattr(pred, "__len__") and not isinstance(pred, str):
                pred = pred[0]
            try:
                pred = int(pred)
            except (ValueError, TypeError):
                pass

            attack_name = self.class_mapping_reverse.get(pred, "Unknown")

            insert_sniffed_flow(
                flow_key=str(key),
                features=feats,
                prediction_label=attack_name,
                timestamp=time.time(),
            )

        self._reset_flows()

    def _reset_flows(self) -> None:
        """Clear current flows and packet counter."""
        self.flow_manager = FlowManager()
        self.packet_count = 0

    def _sniff_loop(self) -> None:
        """Infinite Scapy sniff loop that auto-restarts on error."""
        try:
            sniff(filter=self.bpf_filter, prn=self._packet_handler, store=False)
        except Exception as exc:
            print(f"[Sniffer] Error in sniff loop: {exc}")
            time.sleep(5)
            print("[Sniffer] Restarting sniff loop …")
            self._sniff_loop()  # tail-recursion restart

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    def start_sniffing(self) -> None:
        """Spawn the daemon sniffing thread (idempotent)."""
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="ThreatDetectSniffer",
        )
        self.sniff_thread.start()
        print("[Sniffer] Background sniffing started.")

    def stop_sniffing(self) -> None:
        """
        Graceful stop is non-trivial with Scapy; for now, rely on the main
        process exiting (daemon thread terminates automatically).
        """
        print("[Sniffer] Stop requested – not implemented; terminate main process to halt.")
