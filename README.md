# Network Packet Analyzer

This project implements a **Network Packet Analyzer** that captures and analyzes network packets in real-time. The tool is designed to monitor network traffic and provide insights into various protocols being used, helping users understand the nature of the traffic flowing through a network.

## Features

- **Packet Capture**: Captures network packets in real-time.
- **Protocol Identification**: Identifies common network protocols such as TCP, UDP, ICMP, and others.
- **Packet Analysis**: Provides detailed information about each packet, including source/destination IP addresses, ports, protocols, and packet size.
- **Filtering**: Supports filtering of packets based on protocol or IP address for targeted analysis.
- **Real-time Monitoring**: Displays captured packet information in real-time.

## How It Works

1. **Packet Capture**: The tool captures live network traffic using the `scapy` library.
2. **Packet Analysis**: Each packet is parsed to extract information such as IP addresses, ports, protocols, and more.
3. **Filtering**: You can filter traffic based on protocols like TCP, UDP, or IP addresses for more focused analysis.

## Example Usage

1. **Start Packet Capture**:
   ```bash
   $ sudo python3 packet_analyzer.py
