from scapy.all import sniff, wrpcap, rdpcap
import threading

from scapy.plist import PacketList


class ScapyListener:
    def __init__(self, network_adapter):
        self.network_adapter = network_adapter
        self._stop_sniffing = False
        self.path_to_capture = f'{self.network_adapter}_captured_traffic.pcapng'

    def __packet_callback(self, packet):
        wrpcap(f'{self.network_adapter}_captured_traffic.pcapng', packet, append=True)

    def __stop_filter(self, pkt):
        return self._stop_sniffing

    def __sniff_interface(self, *args, **kwargs):
        sniff(iface=self.network_adapter, prn=self.__packet_callback, store=0, stop_filter=self.__stop_filter)

    def start_capture(self):
        self._capture_thread = threading.Thread(target=self.__sniff_interface, args=(self,))
        self._stop_sniffing = False
        self._capture_thread.start()

    def stop_capture(self):
        self._stop_sniffing = True
        self._capture_thread.join()

    def read_recorded_traffic(self) -> PacketList:
        return rdpcap(self.path_to_capture)

if __name__ == "__main__":
    my_scapy_listener = ScapyListener(network_adapter="Wi-Fi")

    my_scapy_listener.start_capture()

    input("press enter to stop")

    my_scapy_listener.stop_capture()

    packets = my_scapy_listener.read_recorded_traffic()

    for packet in packets:
        print(packet.show())