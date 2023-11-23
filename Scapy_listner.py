from scapy.all import sniff, wrpcap, rdpcap
import threading

class ScapyListener:
    def __init__(self, network_adapter):
        self.network_adapter = network_adapter
        self._capture_thread = threading.Thread(target=self.__sniff_interface, args=(self,))
        self._stop_sniffing = False

    def __packet_callback(self, packet):
        wrpcap('captured_traffic.pcap', packet, append=True)

    def __stop_filter(self, pkt):
        return self._stop_sniffing

    def __sniff_interface(self, *args, **kwargs):
        sniff(iface=self.network_adapter, prn=self.__packet_callback, store=0, stop_filter=self.__stop_filter)

    def start_capture(self):
        self._stop_sniffing = True
        self._capture_thread.start()

    def stop_capture(self):
        self._stop_sniffing = True
        self._capture_thread.join()
        # At this point, the capture thread has completed, and you can proceed with other tasks
        print("Capture complete.")


if __name__ == "__main__":

    my_scapy_listner = ScapyListener(network_adapter="Wi-Fi")

    my_scapy_listner.start_capture()

    # Optionally, you can perform other tasks here while the capture is ongoing
    input("press enter to stop")

    my_scapy_listner.stop_capture()



