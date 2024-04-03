# Packet Sniffer

Packet Sniffer is a simple C# program for monitoring and analyzing network traffic in real-time.

## Introduction

Packet Sniffer is a lightweight tool developed in C# that uses the PcapDotNet library to capture and analyze network packets. It can be used to monitor TCP, UDP, and ICMP traffic, detect suspicious patterns such as SYN floods, and block malicious IPs.

## Features

- Captures network packets in real-time.
- Monitors TCP, UDP, and ICMP protocols.
- Detects SYN floods and blocks malicious IPs.
- Provides live updates on packet counts.
- Saves blocked IPs to a JSON blacklist file.

## Getting Started

To use Packet Sniffer, follow these steps:

1. Clone the repository to your local machine.
2. Open the project in Visual Studio or your preferred C# IDE.
3. Build the solution to compile the program.
4. Run the program and start monitoring network traffic.

## Usage

Packet Sniffer listens for network packets on the specified network interface. It displays live updates on TCP, UDP, and ICMP packet counts. If it detects suspicious activity, such as a SYN flood attack, it blocks the malicious IP address and saves it to a blacklist file.

## Dependencies

- PcapDotNet: A .NET wrapper for WinPcap/Npcap to capture network packets.

## Contributing

Contributions to Packet Sniffer are welcome! Feel free to submit bug reports, feature requests, or pull requests on the GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
