# LizProbe - Network Protocol Parser

A comprehensive network packet analysis tool that provides multi-dimensional feature extraction and protocol analysis capabilities.

## Overview

LizProbe is designed to generate multi-dimensional feature vectors for network traffic analysis, supporting custom cross-features. 

## Features

- **Multi-Protocol Support**: TCP, UDP, VXLAN, VLAN, WiFi, GRE, HTTP, DNS, TLS, ARP, ICMP
- **Deep Packet Inspection**: TLS handshake analysis, HTTP header parsing, DNS query analysis
- **Custom Cross-Features**: Protocol behavior + context logic fusion
- **Flexible Output Formats**: JSON and structured log outputs
- **Statistics and Analytics**: Comprehensive packet and protocol statistics

## System Requirements

- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Compiler**: GCC 7.0+ with C++17 support
- **Dependencies**: 
  - PcapPlusPlus library
  - libpcap
  - pthread
  - libfftw3

## Installation

### Prerequisites

1. **Install PcapPlusPlus**:
   ```bash
   # Download and install PcapPlusPlus
   wget https://github.com/seladb/PcapPlusPlus/releases/download/v25.05/pcapplusplus-25.05-ubuntu-22.04-gcc-11.4.0-x86_64.tar.gz
   tar -xzf pcapplusplus-25.05-ubuntu-22.04-gcc-11.4.0-x86_64.tar.gz
   sudo mv pcapplusplus-25.05-ubuntu-22.04-gcc-11.4.0-x86_64 /root/Documents/
   ```

2. **Install system dependencies**:
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential libpcap-dev libfftw3-dev
   ```

### Compilation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd lizprobe
   ```

2. **Build the project**:
   ```bash
   make clean
   make
   ```

3. **Verify installation**:
   ```bash
   ./pcap_parser --help
   ```

## Usage

### Basic Usage

```bash
# Analyze a PCAP file with default settings
./pcap_parser -i dataset/http_test.pcap

# Analyze with verbose output and JSON format
./pcap_parser -i dataset/dns_test.pcap -v -j

# Analyze with custom output directory
./pcap_parser -i input.pcap -o custom_output
```

### Advanced Usage

```bash
# Filter by protocol
./pcap_parser -i input.pcap -p tcp

# Apply BPF filter
./pcap_parser -i input.pcap -f "tcp port 80"

# Limit packet processing
./pcap_parser -i input.pcap -m 1000

# Combine multiple options
./pcap_parser -i input.pcap -p tcp -f "port 443" -m 500 -v -j -s
```

### Command Line Options

| Option | Long Option | Description |
|--------|-------------|-------------|
| `-i` | `--input_file` | Input PCAP file to analyze (required) |
| `-o` | `--output_dir` | Output directory for logs (default: logs) |
| `-f` | `--filter` | BPF filter expression |
| `-p` | `--protocol` | Filter by specific protocol |
| `-m` | `--max_packets` | Maximum number of packets to process |
| `-v` | `--verbose` | Enable verbose output |
| `-q` | `--quiet` | Suppress normal output |
| `-s` | `--statistics` | Show packet statistics |
| `-j` | `--json` | Output results in JSON format |
| `-h` | `--help` | Show help message |
| `-V` | `--version` | Show version information |

### Supported Protocols

- **Transport Layer**: TCP, UDP
- **Network Layer**: IPv4, IPv6, ICMP, ARP
- **Tunneling**: VXLAN, VLAN, GRE
- **Application Layer**: HTTP, DNS, TLS, DHCP, SMTP, FTP, NTP
- **Wireless**: 802.11 (WiFi)

## Examples

### HTTP Traffic Analysis

```bash
# Analyze HTTP traffic with detailed output
./pcap_parser -i dataset/http_test.pcap -v -j -s

# Filter only HTTP traffic
./pcap_parser -i mixed_traffic.pcap -f "tcp port 80" -p tcp
```

### DNS Analysis

```bash
# Analyze DNS queries and responses
./pcap_parser -i dataset/dns_test.pcap -v -j

# Filter DNS traffic
./pcap_parser -i mixed_traffic.pcap -f "udp port 53" -p udp
```

### TLS/SSL Analysis

```bash
# Analyze TLS handshakes and certificates
./pcap_parser -i dataset/ssl_test.pcap -v -j -s

# Filter HTTPS traffic
./pcap_parser -i mixed_traffic.pcap -f "tcp port 443" -p tcp
```

## Project Structure

```
lizprobe/
├── src/                     # Source code
│   ├── utils/              # Utility classes
│   ├── parsers/            # Protocol parsers
│   └── *.cpp               # Core components
├── include/                # Header files
│   ├── utils/              # Utility headers
│   ├── parsers/            # Parser headers
│   └── *.h                 # Core headers
├── dataset/                # Test PCAP files
├── logs/                   # Output directory
├── build/                  # Build artifacts
├── main.cpp                # Main entry point
├── Makefile                # Build configuration
└── README.md               # This file
```