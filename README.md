
</think># Basic Network Sniffer

A simple Python-based network packet sniffer built using the Scapy library. This tool captures and analyzes network traffic in real-time, helping users understand packet structures, data flow, and common protocols like TCP, UDP, ICMP, and DHCP. Ideal for educational purposes on network forensics and protocol analysis.

**Note:** This tool requires root privileges to capture packets. Use only on networks you own or have permission to monitor. Unauthorized sniffing may violate laws.

## Features

- **Real-time Packet Capture:** Sniffs packets on a specified network interface (e.g., `eth0` or `wlan0`).
- **Protocol Analysis:** Identifies and displays details for IP, TCP, UDP, ICMP, and DHCP packets.
- **Payload Inspection:** Shows raw or decoded payloads (e.g., text for HTTP, structured data for DHCP).
- **Customizable Filters:** Easily modify to focus on specific protocols, ports, or IPs.
- **Educational Output:** Prints source/destination IPs, ports, protocols, and payload snippets for learning.

## Prerequisites

- **Operating System:** Kali Linux (or any Linux distro with Python and Scapy).
- **Python Version:** 3.x (pre-installed on Kali).
- **Libraries:** Scapy (install via `sudo apt install python3-scapy` or `pip3 install scapy`).
- **Permissions:** Root access (run with `sudo`).
- **Network Interface:** Ensure your interface (e.g., `eth0`) is active. Check with `ip a` or `ifconfig`.

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/basic-network-sniffer.git
   cd basic-network-sniffer
   ```

2. Install dependencies (if not already installed):
   ```
   sudo apt update
   sudo apt install python3-scapy
   ```

3. Make the script executable (optional):
   ```
   chmod +x sniffer.py
   ```

## Usage

1. Edit `sniffer.py` to set your network interface (default: `eth0`).
   - Change `interface = "eth0"` to your interface (e.g., `wlan0` for Wi-Fi).

2. Run the sniffer:
   ```
   sudo python3 sniffer.py
   ```

3. Generate traffic to see output (e.g., `ping google.com` or open a browser).

4. Stop with `Ctrl+C`.

### Customization
- **Filters:** Add filters in the `sniff()` call, e.g., `filter="tcp port 80"` for HTTP traffic only.
- **Skip Broadcasts:** Uncomment the broadcast skip in `packet_callback()` to ignore noise like DHCP broadcasts.
- **Advanced Analysis:** Use `packet.show()` in the callback for full packet dissection.

## Examples

### Sample Output
```
Starting packet sniffer on interface: eth0
Press Ctrl+C to stop.
Source IP: 192.168.1.100 | Destination IP: 8.8.8.8 | Protocol: ICMP
ICMP Type: 8 | Code: 0
--------------------------------------------------
Source IP: 192.168.1.100 | Destination IP: 93.184.216.34 | Protocol: TCP
Source Port: 12345 | Destination Port: 80
Payload (text, first 100 chars): GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.68.0
Accept: */*

--------------------------------------------------
Detected DHCP Packet!
Source IP: 0.0.0.0 | Destination IP: 255.255.255.255 | Protocol: UDP
Source Port: 68 | Destination Port: 67
DHCP Message Type: Discover
--------------------------------------------------
```

### Common Scenarios
- **DHCP Traffic:** Shows broadcasts from devices requesting IPs.
- **HTTP Requests:** Decodes TCP payloads for web traffic.
- **Ping (ICMP):** Displays echo requests/responses.

## Contributing

Contributions are welcome! Fork the repo, make changes, and submit a pull request. Ideas:
- Add GUI support (e.g., with Tkinter).
- Integrate with Wireshark for export.
- Enhance protocol decoding (e.g., DNS, ARP).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer


This tool is for educational and ethical use only. The author is not responsible for misuse. Always comply with local laws and obtain permission before sniffing networks.
