# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Jaber Ali Farooqi · W1926781 · University of Westminster                ║
# ║  Final-Year Project – ThreatDetect (Real-Time Network Threat Detection)  ║
# ║  © 2025                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Flow extraction & feature engineering for ThreatDetect
======================================================

This module turns raw packets (live **scapy** sniff or offline PCAP) into
per-flow feature dictionaries compatible with the ML model.

Key abstractions
----------------
* **FlowStats**   – captures all packet-level details for a single bidirectional
  flow (identified by the canonical 5-tuple) and computes 20 handcrafted
  features.
* **FlowManager** – maintains a dictionary of active flows and routes every
  captured packet to the correct `FlowStats` instance.

Why the canonical 5-tuple?
--------------------------
A TCP/UDP “conversation” is bidirectional; we don’t want separate entries for
A→B and B→A.  `FlowManager._get_flow_key` orders `(IP,port)` pairs so the same
key is produced no matter which direction the very first packet travels.

Notes for future work
---------------------
* **Timeout / eviction** – live sniffing will eventually need logic that
  expires long-idle flows to avoid unbounded memory growth.
* **UDP & other protocols** – right now `_get_flow_key` hard-codes TCP checks
  (`haslayer('TCP')`).  Extend to UDP/ICMP if your dataset requires it.
"""

# ---------------------------------------------------------------------------  
# Standard-library imports  
# ---------------------------------------------------------------------------
import statistics
from typing import Dict, Tuple, List, Any

# ---------------------------------------------------------------------------  
# Third-party imports  
# ---------------------------------------------------------------------------
from scapy.all import rdpcap, Packet  # `Packet` is a scapy type hint


# =============================================================================
# -------------------------------  FLOW STATS  --------------------------------
# =============================================================================
class FlowStats:
    """
    Aggregates packet metadata for **one** bidirectional flow and computes
    the 20 features required by the Random-Forest model.

    Parameters
    ----------
    first_packet_time : float
        Epoch timestamp of the very first packet seen for this flow.

    Attributes (high-level)
    -----------------------
    * Forward vs. backward packet sizes / timestamps
    * Sliding counters: `subflow_fwd_bytes`, `subflow_bwd_bytes`
    * TCP window sizes at connection start (`init_win_bytes_*`)
    """
    # ---------------------------------------------------------------------  
    # Construction & update  
    # ---------------------------------------------------------------------
    def __init__(self, first_packet_time: float):
        self.flow_start_time: float = first_packet_time
        self.last_packet_time: float = first_packet_time

        # Per-direction buffers
        self.fwd_packet_sizes: List[int] = []
        self.bwd_packet_sizes: List[int] = []
        self.fwd_timestamps:  List[float] = []
        self.bwd_timestamps:  List[float] = []
        self.all_packet_sizes: List[int] = []

        # TCP initial window sizes (None until we see first packet per dir)
        self.init_win_bytes_forward:  int | None = None
        self.init_win_bytes_backward: int | None = None

        # Sub-flow running totals (used by some CIC-IDS features)
        self.subflow_fwd_bytes: int = 0
        self.subflow_bwd_bytes: int = 0

        # Original tuples are handy for debugging / provenance
        self.forward_tuple:  Tuple[str, str, int, int, int] | None = None
        self.backward_tuple: Tuple[str, str, int, int, int] | None = None

    # ---------------------------------------------------------------------  
    def update(self,
               packet: Packet,
               is_forward: bool,
               packet_time: float,
               packet_size: int,
               tcp_layer):
        """
        Consume **one** packet and refresh in-memory stats.

        Parameters
        ----------
        packet : scapy.Packet
            The raw scapy object (unused except for possible future extensions).
        is_forward : bool
            `True` if the packet direction matches the canonical tuple order.
        packet_time : float
            Epoch timestamp (`packet.time` from scapy).
        packet_size : int
            Raw length in bytes (`len(packet)`).
        tcp_layer : scapy.layers.inet.TCP | None
            The TCP layer (if present) so we can read `window`.
        """
        self.last_packet_time = packet_time
        self.all_packet_sizes.append(packet_size)

        if is_forward:
            self.fwd_packet_sizes.append(packet_size)
            self.fwd_timestamps.append(packet_time)
            self.subflow_fwd_bytes += packet_size
            if self.init_win_bytes_forward is None and tcp_layer:
                self.init_win_bytes_forward = tcp_layer.window
        else:
            self.bwd_packet_sizes.append(packet_size)
            self.bwd_timestamps.append(packet_time)
            self.subflow_bwd_bytes += packet_size
            if self.init_win_bytes_backward is None and tcp_layer:
                self.init_win_bytes_backward = tcp_layer.window

    # ---------------------------------------------------------------------  
    # Feature engineering  
    # ---------------------------------------------------------------------
    def compute_features(self) -> Dict[str, Any]:
        """
        Calculate the 20 engineered features expected by the model.

        Returns
        -------
        dict
            Keys match column names in `feature_order_default`.
            Values are numeric (float/int).  Missing / empty lists → 0.0.
        """
        # ---------- local helper lambdas ---------------------------------
        safe_mean = lambda lst: statistics.mean(lst) if lst else 0.0
        safe_max  = lambda lst: max(lst)            if lst else 0.0
        safe_std  = lambda lst: statistics.pstdev(lst)  if len(lst) > 1 else 0.0
        safe_var  = lambda lst: statistics.pvariance(lst) if len(lst) > 1 else 0.0

        flow_duration = self.last_packet_time - self.flow_start_time or 1e-9

        # ---------- Inter-arrival times (IAT) -----------------------------
        self.fwd_timestamps.sort()
        self.bwd_timestamps.sort()
        all_times = sorted(self.fwd_timestamps + self.bwd_timestamps)

        fwd_iats  = [self.fwd_timestamps[i] - self.fwd_timestamps[i - 1]
                     for i in range(1, len(self.fwd_timestamps))]
        bwd_iats  = [self.bwd_timestamps[i] - self.bwd_timestamps[i - 1]
                     for i in range(1, len(self.bwd_timestamps))]
        flow_iats = [all_times[i]        - all_times[i - 1]
                     for i in range(1, len(all_times))]

        # ---------- Build feature dict -----------------------------------
        return {
            ' Fwd Packet Length Mean':   safe_mean(self.fwd_packet_sizes),
            ' Fwd Packet Length Max':    safe_max(self.fwd_packet_sizes),
            ' Avg Fwd Segment Size':     safe_mean(self.fwd_packet_sizes),
            ' Subflow Fwd Bytes':        self.subflow_fwd_bytes,
            'Total Length of Fwd Packets': sum(self.fwd_packet_sizes),

            ' Flow IAT Max':             safe_max(flow_iats),
            ' Average Packet Size':      safe_mean(self.all_packet_sizes),
            ' Bwd Packet Length Std':    safe_std(self.bwd_packet_sizes),
            ' Flow Duration':            flow_duration,
            ' Avg Bwd Segment Size':     safe_mean(self.bwd_packet_sizes),

            ' Bwd Packets/s':            len(self.bwd_packet_sizes) / flow_duration,
            ' Packet Length Mean':       safe_mean(self.all_packet_sizes),
            'Init_Win_bytes_forward':    self.init_win_bytes_forward  or 0,
            ' Init_Win_bytes_backward':  self.init_win_bytes_backward or 0,

            ' Packet Length Std':        safe_std(self.all_packet_sizes),
            ' Fwd IAT Max':              safe_max(fwd_iats),
            ' Fwd Packet Length Std':    safe_std(self.fwd_packet_sizes),
            ' Packet Length Variance':   safe_var(self.all_packet_sizes),
            ' Total Length of Bwd Packets': sum(self.bwd_packet_sizes),

            ' Flow Packets/s': ((len(self.fwd_packet_sizes) +
                                 len(self.bwd_packet_sizes)) / flow_duration)
        }


# =============================================================================
# -------------------------------  FLOW MANAGER  ------------------------------
# =============================================================================
class FlowManager:
    """
    Keeps track of *many* `FlowStats` objects keyed by a canonical 5-tuple.

    Methods
    -------
    process_packet(packet)
        Feed one live-captured scapy packet into the flow dictionary.
    parse_pcap_file(path)
        Offline helper → iterates through every packet in a PCAP and returns
        the completed `self.flows` dict.
    """

    def __init__(self):
        self.flows: Dict[Tuple[str, str, int, int, int], FlowStats] = {}

    # ---------------------------------------------------------------------  
    def _get_flow_key(self,
                      ip_src: str,
                      ip_dst: str,
                      sport: int,
                      dport: int,
                      proto: int) -> Tuple[str, str, int, int, int]:
        """
        Return an **ordered** 5-tuple that is identical for A→B and B→A.

        The “smaller” `(IP,port)` pair comes first lexicographically.
        """
        if (ip_src, sport) < (ip_dst, dport):
            return (ip_src, ip_dst, sport, dport, proto)
        else:
            return (ip_dst, ip_src, dport, sport, proto)

    # ---------------------------------------------------------------------  
    def process_packet(self, packet: Packet) -> None:
        """
        Consume a single scapy packet during real-time capture.

        * Non-TCP or non-IPv4 packets are ignored (model expects TCP flows).
        * Detects direction (fwd/bwd) relative to canonical flow key.
        """
        if not (packet.haslayer('IP') and packet.haslayer('TCP')):
            return                                 # skip unsupported protocols

        ip_layer  = packet['IP']
        tcp_layer = packet['TCP']

        key = self._get_flow_key(
            ip_src=ip_layer.src,
            ip_dst=ip_layer.dst,
            sport=tcp_layer.sport,
            dport=tcp_layer.dport,
            proto=ip_layer.proto
        )

        pkt_time  = packet.time
        pkt_size  = len(packet)

        # Determine direction relative to the canonical key
        if (ip_layer.src, tcp_layer.sport) < (ip_layer.dst, tcp_layer.dport):
            is_forward = (ip_layer.src == key[0] and tcp_layer.sport == key[2])
        else:
            is_forward = (ip_layer.src == key[1] and tcp_layer.sport == key[3])

        # Create new FlowStats if this is the very first packet
        if key not in self.flows:
            self.flows[key] = FlowStats(pkt_time)

        self.flows[key].update(packet, is_forward, pkt_time, pkt_size, tcp_layer)

    # ---------------------------------------------------------------------  
    def parse_pcap_file(self, pcap_path: str):
        """
        Offline parsing of a `.pcap` file.

        Reads every packet via scapy’s `rdpcap`, routes them through
        `process_packet`, then returns the populated `self.flows` dict.

        Returns
        -------
        dict[tuple, FlowStats]
            Same object as `self.flows` for convenience/chaining.
        """
        for pkt in rdpcap(pcap_path):
            self.process_packet(pkt)
        return self.flows
