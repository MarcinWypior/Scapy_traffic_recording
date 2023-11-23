from scapy.all import sniff, wrpcap, rdpcap
import os
import threading
import time

stop_sniffing = False
network_adapter = 'Wi-Fi'

def packet_callback(packet):
    wrpcap('captured_traffic.pcap', packet, append=False)


def stop_filter(pkt):
    return stop_sniffing


def start_capture(interface):
    sniff(iface=interface, prn=packet_callback, store=0, stop_filter=stop_filter)



capture_thread = threading.Thread(target=start_capture, args=(network_adapter,))

# Start the capture thread
capture_thread.start()

# Optionally, you can perform other tasks here while the capture is ongoing
input("press enter to quit")

stop_sniffing = True
capture_thread.join()

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
