# Orbital - Network Packet Analyzer

A powerful network packet analysis tool with a modern, user-friendly interface. Built with Python and Tkinter.

## Features

- Real-time packet capture and analysis
- Protocol-specific packet decoding (TCP, UDP, DNS, HTTP, ICMP)
- Advanced packet filtering capabilities
- Packet replay and export functionality
- Beautiful dark-themed interface
- Detailed packet statistics and analysis

## Installation

### From Executable
1. Download the latest release from the Releases page.
2. Run `Orbital.exe` (requires administrator privileges)

### From Source
1. Clone the repository.

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the tool:
```bash
python orbital.py
```

## Usage

1. Run the tool as administrator
2. Select your network interface
3. Click "Start Capture" to begin packet capture
4. Use the right-click menu for additional options:
   - Send to Decoder
   - Quick Inspect
   - Replay Packet
   - Export Packet
   - Filter Options

## Building from Source

To create an executable:

```bash
python build.py
```

## Requirements

- Windows 10 or later
- Administrator privileges
- Network interface with packet capture capabilities

## Disclaimer

This tool is for educational and network analysis purposes only. Always ensure you have proper authorization before capturing network traffic. 
