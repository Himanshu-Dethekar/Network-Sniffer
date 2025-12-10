from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Extracts and displays useful information.
    """
    if IP in packet:  # Check if it's an IP packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Map protocol number to name
        proto_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, f"Unknown ({protocol})")
        
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {proto_name}")
        
        # Display payload (first 50 bytes) if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
            if payload:
                print(f"Payload (first 50 bytes): {payload[:50]}")
        elif packet.haslayer(ICMP):
            print(f"ICMP Type: {packet[ICMP].type} | Code: {packet[ICMP].code}")
        
        print("-" * 50)  # Separator for readability

# Main function to start sniffing
def main():
    interface = "eth0"  # Change to your network interface (e.g., wlan0 for Wi-Fi)
    print(f"Starting packet sniffer on interface: {interface}")
    print("Press Ctrl+C to stop.")
    
    # Sniff packets indefinitely, calling packet_callback for each
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
