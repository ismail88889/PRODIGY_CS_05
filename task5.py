import argparse
import os
from scapy.all import sniff, Ether, IP, TCP, UDP

class PacketSniffer:
    def __init__(self):
        self.observers = []

    def register_observer(self, observer):
        self.observers.append(observer)

    def notify_observers(self, packet):
        for observer in self.observers:
            observer.update(packet)

    def listen(self, interface=None):
        sniff(iface=interface, prn=self.handle_packet, store=False)

    def handle_packet(self, packet):
        self.notify_observers(packet)

class PacketAnalyzer:
    def update(self, packet):
        if Ether in packet:
            ether_frame = packet[Ether]
            print(f"\nEthernet Frame: {ether_frame.src} -> {ether_frame.dst} | Type: {ether_frame.type}")
            
            if IP in packet:
                ip_packet = packet[IP]
                print(f"IP Packet: {ip_packet.src} -> {ip_packet.dst} | Protocol: {ip_packet.proto}")
                
                if TCP in packet:
                    tcp_segment = packet[TCP]
                    print(f"TCP Segment: {tcp_segment.sport} -> {tcp_segment.dport}")
                    print(f"Flags: {tcp_segment.flags}")
                    if hasattr(tcp_segment, 'load'):
                        print(f"Payload: {tcp_segment.load}")
                
                elif UDP in packet:
                    udp_segment = packet[UDP]
                    print(f"UDP Segment: {udp_segment.sport} -> {udp_segment.dport}")
                    if hasattr(udp_segment, 'load'):
                        print(f"Payload: {udp_segment.load}")

class OutputToScreen:
    def __init__(self, subject, display_data):
        self.subject = subject
        self.display_data = display_data
        self.subject.register_observer(self)

    def update(self, packet):
        if self.display_data:
            print(packet.show())
        else:
            print(f"Captured Packet: {packet.summary()}")

def main():
    parser = argparse.ArgumentParser(description="Network packet analyzer")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Interface from which Ethernet frames will be captured (monitors "
             "all available interfaces by default)."
    )
    parser.add_argument(
        "-d", "--data",
        action="store_true",
        help="Output packet data during capture."
    )
    _args = parser.parse_args()

    if os.getuid() != 0:
        raise SystemExit("Error: Permission denied. This application requires "
                         "administrator privileges to run.")

    sniffer = PacketSniffer()
    analyzer = PacketAnalyzer()

    OutputToScreen(
        subject=sniffer,
        display_data=_args.data
    )

    sniffer.register_observer(analyzer)

    try:
        sniffer.listen(_args.interface)
    except KeyboardInterrupt:
        raise SystemExit("[!] Aborting packet capture...")

if __name__ == "__main__":
    main()

