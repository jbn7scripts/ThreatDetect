import statistics
from scapy.all import rdpcap

class FlowStats:
    """
    Holds packet-level data for a single flow and computes the requested features.
    """
    def __init__(self, first_packet_time):
        self.flow_start_time = first_packet_time
        self.last_packet_time = first_packet_time

        self.fwd_packet_sizes = []
        self.bwd_packet_sizes = []
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        self.all_packet_sizes = []

        self.init_win_bytes_forward = None
        self.init_win_bytes_backward = None

        # Subflow counters 
        self.subflow_fwd_bytes = 0
        self.subflow_bwd_bytes = 0

        # We'll store the "original" 5-tuple (for reference) if needed
        self.forward_tuple = None
        self.backward_tuple = None

    def update(self, packet, is_forward, packet_time, packet_size, tcp_layer):
        """
        Update flow stats with one packet.
        """
        self.last_packet_time = packet_time
        self.all_packet_sizes.append(packet_size)

        # Record forward/backward
        if is_forward:
            self.fwd_packet_sizes.append(packet_size)
            self.fwd_timestamps.append(packet_time)
            self.subflow_fwd_bytes += packet_size
            # Initialize window bytes
            if self.init_win_bytes_forward is None and tcp_layer:
                self.init_win_bytes_forward = tcp_layer.window
        else:
            self.bwd_packet_sizes.append(packet_size)
            self.bwd_timestamps.append(packet_time)
            self.subflow_bwd_bytes += packet_size
            # Initialize window bytes
            if self.init_win_bytes_backward is None and tcp_layer:
                self.init_win_bytes_backward = tcp_layer.window

    def compute_features(self):
        """
        Compute the 20 requested features. Returns a dict keyed by the same feature names
        used in your Flask form / feature_order list.
        """
        # Helper safe stats:
        def safe_mean(lst): return statistics.mean(lst) if lst else 0.0
        def safe_max(lst): return max(lst) if lst else 0.0
        def safe_std(lst): return statistics.pstdev(lst) if len(lst) > 1 else 0.0
        def safe_var(lst): return statistics.pvariance(lst) if len(lst) > 1 else 0.0

        flow_duration = self.last_packet_time - self.flow_start_time
        if flow_duration <= 0:
            flow_duration = 1e-9

        # Sort timestamps for IAT calculations
        self.fwd_timestamps.sort()
        self.bwd_timestamps.sort()
        all_times = sorted(self.fwd_timestamps + self.bwd_timestamps)

        # Compute IAT lists
        fwd_iats = [
            self.fwd_timestamps[i] - self.fwd_timestamps[i - 1]
            for i in range(1, len(self.fwd_timestamps))
        ]
        bwd_iats = [
            self.bwd_timestamps[i] - self.bwd_timestamps[i - 1]
            for i in range(1, len(self.bwd_timestamps))
        ]
        flow_iats = [
            all_times[i] - all_times[i - 1]
            for i in range(1, len(all_times))
        ]

        features_dict = {
            ' Fwd Packet Length Mean': safe_mean(self.fwd_packet_sizes),
            ' Fwd Packet Length Max': safe_max(self.fwd_packet_sizes),
            ' Avg Fwd Segment Size': safe_mean(self.fwd_packet_sizes),  
            ' Subflow Fwd Bytes': self.subflow_fwd_bytes,
            'Total Length of Fwd Packets': sum(self.fwd_packet_sizes),
            ' Flow IAT Max': safe_max(flow_iats),
            ' Average Packet Size': safe_mean(self.all_packet_sizes),
            ' Bwd Packet Length Std': safe_std(self.bwd_packet_sizes),
            ' Flow Duration': flow_duration,
            ' Avg Bwd Segment Size': safe_mean(self.bwd_packet_sizes),
            ' Bwd Packets/s': len(self.bwd_packet_sizes) / flow_duration,
            ' Packet Length Mean': safe_mean(self.all_packet_sizes),
            'Init_Win_bytes_forward': self.init_win_bytes_forward or 0,
            ' Init_Win_bytes_backward': self.init_win_bytes_backward or 0,
            ' Packet Length Std': safe_std(self.all_packet_sizes),
            ' Fwd IAT Max': safe_max(fwd_iats),
            ' Fwd Packet Length Std': safe_std(self.fwd_packet_sizes),
            ' Packet Length Variance': safe_var(self.all_packet_sizes),
            ' Total Length of Bwd Packets': sum(self.bwd_packet_sizes),
            ' Flow Packets/s': (len(self.fwd_packet_sizes) + len(self.bwd_packet_sizes)) / flow_duration
        }
        return features_dict

class FlowManager:
    """
    Manages a dictionary of flows keyed by 5-tuple, or some canonical representation.
    Provides methods to process packets (online sniffing) or parse PCAP (offline).
    """
    def __init__(self):
        # flows dict: key -> FlowStats
        self.flows = {}

    def _get_flow_key(self, ip_src, ip_dst, sport, dport, proto):
        """
        Return a canonical 5-tuple so that forward/backward is always recognized.
        """
        # Sort the tuple so that the 'lesser' side is always first in the key
        if (ip_src, sport) < (ip_dst, dport):
            return (ip_src, ip_dst, sport, dport, proto)
        else:
            return (ip_dst, ip_src, dport, sport, proto)

    def process_packet(self, packet):
        """
        Handle a single scapy packet in real-time sniffing.
        Identify the flow, update the corresponding FlowStats object.
        """
        if not packet.haslayer('IP') or not packet.haslayer('TCP'):
            return

        ip_layer = packet['IP']
        tcp_layer = packet['TCP']

        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        proto = ip_layer.proto 

        # Determine canonical key
        key = self._get_flow_key(ip_src, ip_dst, sport, dport, proto)
        packet_time = packet.time
        packet_size = len(packet)

        # Is this packet forward or backward relative to the key?
        # If the key was (src, dst, sport, dport),
        # forward means IP=src, backward means IP=dst.
        if (ip_src, sport) < (ip_dst, dport):
            is_forward = (ip_src == key[0] and sport == key[2])
        else:
            is_forward = (ip_src == key[1] and sport == key[3])

        # Create if doesn't exist
        if key not in self.flows:
            self.flows[key] = FlowStats(packet_time)
        flow_stats = self.flows[key]

        flow_stats.update(packet, is_forward, packet_time, packet_size, tcp_layer)

    def parse_pcap_file(self, pcap_path):
        """
        Offline parsing of a .pcap file. This can be used in your upload route
        to generate flows from the entire file, then compute features for each flow.
        """
        packets = rdpcap(pcap_path)
        for pkt in packets:
            self.process_packet(pkt)
        return self.flows
