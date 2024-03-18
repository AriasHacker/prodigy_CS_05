
Task-05:
Network Packet Analyzer

Develop a packet sniffer tool that captures and analyzes network packets.
Display relevant information such as source and destination IP addresses, protocols, and payload data.
Ensure the ethical use of the tool for educational purposes.

here is the code for capturaing packets in kali linux using python .

#!/usr/bin/env python3

import scapy.all as scapy

def sniff_packets(interface, protocol):
    """
    Sniff packets on the specified interface and filter by protocol.
    """
    try:
        scapy.sniff(iface=interface, store=False, prn=process_packet, filter=protocol)
    except KeyboardInterrupt:
        print("Exiting...")

def process_packet(packet):
    """
    Process each captured packet.
    """
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        payload = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None

        print(f"Source IP: {source_ip} --> Destination IP: {destination_ip} | Protocol: {protocol}")
        if payload:
            print("Payload:")
            print(payload)
        print("="*50)

if __name__ == "__main__":
    interface = input("Enter interface to sniff on (e.g., eth0): ")
    protocol = input("Enter protocol to filter (e.g., tcp, udp, icmp): ")

    print(f"Sniffing packets on interface {interface} for protocol {protocol}...")

    sniff_packets(interface, protocol)
