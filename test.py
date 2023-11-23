from scapy.all import sniff, wrpcap, rdpcap
import os
import threading
import time

def packet_callback(packet):
    wrpcap('captured_traffic.pcap', packet, append=True)


def start_capture(interface, duration):
    sniff(iface=interface, prn=packet_callback, store=0, timeout=duration)


# Replace 'Ethernet' with the name of your network adapter
network_adapter = 'Wi-Fi'

# Set the duration for which you want to capture traffic (in seconds)
duration = 1  # Adjust this according to your needs

# Create a thread for packet capture
capture_thread = threading.Thread(target=start_capture, args=(network_adapter, duration))

# Start the capture thread
capture_thread.start()

# Wait for the capture thread to complete
capture_thread.join()

# Optionally, you can perform other tasks here while the capture is ongoing

# At this point, the capture thread has completed, and you can proceed with other tasks
print("Capture complete.")

pcap_file_path = 'captured_traffic.pcap'

# Read the packets from the pcap file
packets = rdpcap(pcap_file_path)

# Now, 'packets' is a list of packet objects

# You can iterate through the list and access information about each packet
for packet in packets:
    # Process each packet as needed
    print(packet.summary())
    print(packet.show())
