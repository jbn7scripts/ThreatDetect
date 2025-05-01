# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Jaber Ali Farooqi · W1926781 · University of Westminster                ║
# ║  Final-Year Project – ThreatDetect (Real-Time Network Threat Detection)  ║
# ║  © 2025                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
import time
import csv
import threading
import statistics
import argparse
from datetime import datetime
from scapy.all import sniff, rdpcap

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
        Compute the 20 requested features. Returns a dict keyed by the same feature names.
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
    Manages a dictionary of flows keyed by 5-tuple.
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
        Offline parsing of a .pcap file to generate flows.
        """
        print(f"Parsing PCAP file: {pcap_path}")
        packets = rdpcap(pcap_path)
        for pkt in packets:
            self.process_packet(pkt)
        return self.flows


class NetworkDataCollector:
    def __init__(self, 
                output_file="network_data.csv", 
                traffic_label="normal",
                batch_size=40, 
                duration=None,
                bpf_filter="tcp"):
        
        self.output_file = output_file
        self.traffic_label = traffic_label
        self.batch_size = batch_size
        self.duration = duration
        self.bpf_filter = bpf_filter
        
        self.flow_manager = FlowManager()
        self.sniff_thread = None
        self.packet_count = 0
        self.start_time = None
        self.is_running = False
        
        # Column headers for CSV
        self.feature_names = [
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
            ' Flow Packets/s',
            'Label'  # Added label column
        ]
        
        # Initialize CSV file with headers
        self._init_csv()
    
    def _init_csv(self):
        """Initialize the CSV file with headers"""
        with open(self.output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(self.feature_names)
        print(f"Initialized CSV file: {self.output_file}")
    
    def _packet_handler(self, packet):
        """Handle each packet as it's sniffed"""
        self.flow_manager.process_packet(packet)
        self.packet_count += 1
        
        # Check if we need to process a batch
        if self.packet_count >= self.batch_size:
            self._process_batch()
            
        # Check if we've reached the duration limit
        if self.duration and time.time() - self.start_time >= self.duration:
            print(f"Duration limit of {self.duration} seconds reached.")
            self.stop_sniffing()
    
    def _process_batch(self):
        """Process a batch of packets and write to CSV"""
        print(f"Processing batch of {self.packet_count} packets...")
        flows_dict = self.flow_manager.flows
        
        # Process each flow
        with open(self.output_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            
            for key, flow_stats in flows_dict.items():
                # Get features as a dictionary
                features = flow_stats.compute_features()
                
                # Convert to list in the correct order for CSV
                row = [features[feature] for feature in self.feature_names[:-1]]
                # Add the label
                row.append(self.traffic_label)
                
                # Write to CSV
                writer.writerow(row)
        
        # Reset for the next batch
        self.flow_manager = FlowManager()
        self.packet_count = 0
        print(f"Processed {len(flows_dict)} flows. Ready for next batch.")
    
    def _sniff_loop(self):
        """Background thread for sniffing packets"""
        self.start_time = time.time()
        try:
            # The stop_filter will be called after each packet
            sniff(
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"Error in sniffing thread: {str(e)}")
    
    def start_sniffing(self):
        """Start the sniffing process in a background thread"""
        if self.sniff_thread and self.sniff_thread.is_alive():
            print("Sniffing is already running.")
            return
        
        self.is_running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        print(f"Started sniffing with filter: {self.bpf_filter}")
        print(f"Data will be collected with label: {self.traffic_label}")
    
    def stop_sniffing(self):
        """Stop the sniffing process"""
        self.is_running = False
        print("Stopping sniffing...")
        
        # Process any remaining packets
        if self.packet_count > 0:
            self._process_batch()
    
    def process_pcap(self, pcap_file):
        """Process a pcap file and output to CSV"""
        self.flow_manager = FlowManager()
        self.flow_manager.parse_pcap_file(pcap_file)
        
        # Process all flows
        with open(self.output_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            
            for key, flow_stats in self.flow_manager.flows.items():
                # Get features as a dictionary
                features = flow_stats.compute_features()
                
                # Convert to list in the correct order for CSV
                row = [features[feature] for feature in self.feature_names[:-1]]
                # Add the label
                row.append(self.traffic_label)
                
                # Write to CSV
                writer.writerow(row)
        
        print(f"Processed {len(self.flow_manager.flows)} flows from {pcap_file}")
        return len(self.flow_manager.flows)


def main():
    parser = argparse.ArgumentParser(description='Network Traffic Data Collector')
    parser.add_argument('--output', '-o', type=str, default=f'network_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
                        help='Output CSV file path')
    parser.add_argument('--label', '-l', type=str, default='normal',
                        help='Traffic label (normal, ddos, portscanning, etc.)')
    parser.add_argument('--batch-size', '-b', type=int, default=40,
                        help='Number of packets to process in each batch')
    parser.add_argument('--duration', '-d', type=int, default=None,
                        help='Duration to collect in seconds (None means run until stopped)')
    parser.add_argument('--filter', '-f', type=str, default='tcp',
                        help='Berkeley Packet Filter (BPF) filter')
    parser.add_argument('--pcap', '-p', type=str, default=None,
                        help='Process a PCAP file instead of live traffic')
    
    args = parser.parse_args()
    
    collector = NetworkDataCollector(
        output_file=args.output,
        traffic_label=args.label,
        batch_size=args.batch_size,
        duration=args.duration,
        bpf_filter=args.filter
    )
    
    if args.pcap:
        # Process a PCAP file
        collector.process_pcap(args.pcap)
    else:
        # Live sniffing
        try:
            collector.start_sniffing()
            print("Press Ctrl+C to stop sniffing...")
            while collector.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nSniffing interrupted by user.")
            collector.stop_sniffing()
    
    print(f"Data collection completed. Results saved to {args.output}")


if __name__ == "__main__":
    main()