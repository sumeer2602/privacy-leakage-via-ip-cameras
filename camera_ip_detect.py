import pyshark

# Load the pcap file
cap = pyshark.FileCapture('data/new_capture.pcap')

# Display information about the first 5 packets
for i, pkt in enumerate(cap):
    if i >= 5:
        break
    print(pkt)