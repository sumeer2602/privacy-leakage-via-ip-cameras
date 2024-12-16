import pyshark
import argparse
import re
from datetime import datetime
import pandas as pd


# Define the IPs for the camera and Alibaba cloud server
camera_ip = '192.168.1.169'
server_ip = '47.88.37.113'

def convert_time_to_standard(packet_time):
    # Convert to datetime object
    timestamp = datetime.fromtimestamp(packet_time.timestamp())
    
    # Format it as a string
    formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    return formatted_time

def analyze_pcap(file_path=None):
    # Dictionary to track connections and events
    connection_tracker = {}
    seen_packets = set()
    pkt_count = 0
    
    packet_data_list = []
    seen = False

    # Create capture object based on input
    if file_path:
        capture = pyshark.FileCapture(file_path, display_filter=f'ip.addr == {camera_ip} and ip.addr == {server_ip}')
    else:
        capture = pyshark.LiveCapture(interface='wlx9418655dbac0', display_filter=f'ip.addr == {camera_ip} and ip.addr == {server_ip}')

    # Iterate through packets
    for packet in capture:
        try:
            # Verify packet involves our specific IPs
            if not (packet.ip.src in [camera_ip, server_ip] and packet.ip.dst in [camera_ip, server_ip]):
                continue

            # Connection key
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

            # Check for TCP packet
            if hasattr(packet, 'tcp'):
                # Check for SYN flag (start of connection)
                if (packet.tcp.flags == '0x0002' or packet.tcp.flags == '0x0012') and not connection_data['syn_seen']:
                    connection_data['syn_seen'] = True

                # Check for HTTP 200 OK response with application/json content-type
                if hasattr(packet, 'http'):
                    try:
                        # Try to get raw payload for detailed checking
                        raw_payload = packet.tcp.payload.replace(':', '')
                        raw_payload = bytes.fromhex(raw_payload).decode(errors='ignore')
                        
                        # Detailed HTTP response checking
                        if ("HTTP/1.1 200 OK" in raw_payload and 
                            "application/json" in raw_payload):
                            connection_data['http_response_seen'] = True
                    except Exception:
                        # Fallback to PyShark attributes if raw payload parsing fails
                        print("EXCEPTION OCURRED=======================")
                        if (packet.http.response_code == '200' and 
                            hasattr(packet.http, 'content_type') and 
                            'application/json' in packet.http.content_type):
                            connection_data['http_response_seen'] = True

                # Check for FIN flag (end of connection)
                # if int(packet.tcp.flags, 16) & 0x01:  # FIN flag is the least significant bit
                #     connection_data['fin_seen'] = True

                # More precise bitwise FIN flag check
                fin_flag = 0x01
                fin_ack_flags = 0x11  # FIN and ACK

                packet_flags = int(packet.tcp.flags, 16)
                if (packet_flags == fin_flag) or (packet_flags == fin_ack_flags):
                    if not connection_data['fin_seen']:
                        connection_data['fin_seen'] = True
                
                
                
                # Check for retransmission using sequence and acknowledgment numbers
                if hasattr(packet.tcp, 'seq') and hasattr(packet.tcp, 'ack_raw'):
                    seq_num = int(packet.tcp.seq)
                    ack_num = int(packet.tcp.ack_raw)

                    if (seq_num, ack_num) in seen_packets:
                        continue  # Skip retransmission

                    seen_packets.add((seq_num, ack_num))

                pkt_count += 1

                # If SYN, HTTP 200 OK, and FIN are seen, count it as a motion detection event
                if (connection_data['syn_seen'] and 
                    connection_data['http_response_seen'] and 
                    connection_data['fin_seen']):
                    connection_data['motion_event_count'] += 1
                    # print(f"[{convert_time_to_standard(packet.sniff_time)}] Motion detection event detected! Total events: {connection_data['motion_event_count']}")
                    print(f"[{convert_time_to_standard(packet.sniff_time)}] Motion detection event detected!")
                    print(f"Number of Packets in the Flow: {pkt_count}\n")
                    seen = True
                    
                    # Reset for the next potential event
                    connection_data['syn_seen'] = False
                    connection_data['http_response_seen'] = False
                    connection_data['fin_seen'] = False
                    pkt_count = 0

            if seen:
                packet_data_list.append({
                    "timestamp": convert_time_to_standard(packet.sniff_time),
                    "motion_event": 1,
                    # "packet_count": pkt_count
                })
                seen = False
            else:
                packet_data_list.append({
                    "timestamp": convert_time_to_standard(packet.sniff_time),
                    "motion_event": 0,
                    # "packet_count": pkt_count
                })
                
                
        
        except AttributeError as e:
            # Ignore packets that don't have expected attributes
            print(f"Skipping packet: {e}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    # Print the total number of motion events detected
    total_events = sum([data['motion_event_count'] for data in connection_tracker.values()])
    print(f"Total motion detection events detected: {total_events}")
    
    packet_df = pd.DataFrame(packet_data_list)
    # packet_df.to_csv("output_motion.csv", index=False)
    
    print("Analysis complete!")

def main():
    # Initialize argparse
    parser = argparse.ArgumentParser(description="Analyze pcap file or live traffic for motion detection events.")
    parser.add_argument("file", nargs="?", help="Path to the pcap file. Leave empty to analyze live traffic.")
    args = parser.parse_args()
    
    analyze_pcap(args.file)

if __name__ == '__main__':
    main()