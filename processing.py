from scapy.all import *
import re

# Define the IPs for the camera and Alibaba cloud server
camera_ip = '192.168.1.169'
server_ip = '47.88.37.113'

# Define a dictionary to track ongoing connections and events
events = []


# Function to analyze each packet and check for motion detection events
def analyze_packet(packet, connection_tracker, seen_packets):
    try:
        # Only process IP packets
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Check if the packet is between the camera and the server
            if (src_ip == camera_ip and dst_ip == server_ip) or (src_ip == server_ip and dst_ip == camera_ip):
                connection_key = (camera_ip, server_ip)

                # Initialize connection tracker for this pair if not already tracked
                if connection_key not in connection_tracker:
                    connection_tracker[connection_key] = {
                        'syn_seen': False,
                        'http_response_seen': False,
                        'fin_seen': False,
                        'motion_event_count': 0,

                    }

                connection_data = connection_tracker[connection_key]

                # Check for SYN flag (Start of communication)
                if TCP in packet:
                    # If SYN is set alone, it's the start of connection
                    if (packet[TCP].flags == 'S' or packet[TCP].flags == 'SA') and not connection_data['syn_seen']:
                        connection_data['syn_seen'] = True
                        print(f"[{packet.time}] SYN packet from {src_ip} to {dst_ip} (Start of connection - [{packet[TCP].flags}])")

                # Check for HTTP 200 OK with application/json content-type (motion event)
                if TCP in packet and Raw in packet:
                    raw_payload = packet[Raw].load.decode(errors='ignore')
                    if "HTTP/1.1 200 OK" in raw_payload and "application/json" in raw_payload :
                        connection_data['http_response_seen'] = True
                        print(f"[{packet.time}] HTTP 200 OK response from {src_ip} to {dst_ip} (Motion event response)")

                # Check for FIN flag (End of connection)
                if TCP in packet:
                    # Check if FIN is set (either with ACK or alone)
                    if packet[TCP].flags & 0x01:  # FIN flag is the least significant bit
                        if not connection_data['fin_seen']:
                            connection_data['fin_seen'] = True
                            print(f"[{packet.time}] FIN packet from {src_ip} to {dst_ip} (End of connection)")

                # Check if the packet is a retransmission
                if TCP in packet:
                    seq_num = packet[TCP].seq
                    ack_num = packet[TCP].ack

                    # Use the sequence and acknowledgment numbers to track packets
                    if (seq_num, ack_num) in seen_packets:
                        return  # Skip this retransmission and don't process it as part of a motion event

                    # Mark this packet's seq and ack numbers as seen
                    seen_packets.add((seq_num, ack_num))

                # If SYN, HTTP 200 OK, and FIN are seen, count it as a motion detection event
                if connection_data['syn_seen'] and connection_data['http_response_seen'] and connection_data['fin_seen']:
                    connection_data['motion_event_count'] += 1
                    print(f"[{packet.time}] Motion detection event detected! Total events: {connection_data['motion_event_count']}")
                    # Reset for the next potential event
                    connection_data['syn_seen'] = False
                    connection_data['http_response_seen'] = False
                    connection_data['fin_seen'] = False

    except Exception as e:
        print(f"Error processing packet: {e}")
        pass

# Function to process the pcap file and analyze packets
def process_pcap(file_path=None):
    # Dictionary to track connections between camera and server
    connection_tracker = {}
    seen_packets = set()

    if file_path:
        # If a file is provided, process it
        print(f"Analyzing pcap file: {file_path}")
        packets = rdpcap(file_path)
        for packet in packets:
            analyze_packet(packet, connection_tracker, seen_packets)
    else:
        # If no file is provided, analyze live traffic
        print(f"Analyzing live traffic between {camera_ip} and {server_ip}...")
        sniff(filter=f"ip and (src {camera_ip} and dst {server_ip}) or (src {server_ip} and dst {camera_ip})", 
              prn=lambda x: analyze_packet(x, connection_tracker, seen_packets), store=0)

    # Print the total number of motion events detected
    total_events = sum([data['motion_event_count'] for data in connection_tracker.values()])
    print(f"Total motion detection events detected: {total_events}")
    
    print("Analysis complete!")


# Example usage
if __name__ == '__main__':
    pcap_file = None  # Set to a file path for pcap analysis or leave as None for live traffic analysis
    process_pcap(pcap_file)
