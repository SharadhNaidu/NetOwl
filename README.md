# NetOwl - Network Device Scanner and OS Fingerprinter

A desktop application for discovering connected devices on your local network and identifying their operating systems through active network probing.

## Features

- **Device Discovery**: Active ARP scanning to find all devices on your network
- **OS Fingerprinting**: TCP/IP stack fingerprinting using TTL values to guess device operating systems
- **Clean GUI**: Minimalist monochrome interface built with Tkinter
- **Non-blocking Scan**: Network scanning runs in background threads to keep the UI responsive
- **Device Details**: View detailed information about discovered devices

## System Requirements

- Python 3.6+
- Linux, macOS, or Windows
- Root/Administrator privileges (required for raw packet manipulation)
- Tkinter (usually included with Python)

## Installation

1. Clone or download the project:
```bash
cd /home/sharadhnaidu/Desktop/NetOwl
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Linux/macOS

Run the application with root privileges:
```bash
sudo python3 main.py
```

### Windows

Run Command Prompt or PowerShell as Administrator:
```bash
python main.py
```

## How It Works

### Feature 1: Device Discovery (ARP Scan)

1. Click "Scan Network"
2. The application automatically detects your local network range (e.g., 192.168.1.0/24)
3. Sends ARP broadcast requests to all IP addresses in the range
4. Each online device responds with its IP and MAC address
5. Results appear in the device list

### Feature 2: OS Fingerprinting (TTL Analysis)

After discovering devices, the application:

1. Sends TCP SYN packets to each device
2. Analyzes the TTL (Time-to-Live) value from responses
3. Makes an educated guess about the OS:
   - **TTL ≤ 64**: Linux, macOS, or Android
   - **TTL 65-128**: Windows
   - **TTL 129-255**: Network devices (routers, switches)

## User Interface

### Main Window Components

- **Title**: "NetOwl - Network Scanner"
- **Control Panel**: 
  - "Scan Network" button to start/stop scans
  - Status display showing scan progress
- **Device List**: Scrollable list of discovered devices (IP and MAC)
- **Details Panel**: Shows full information about selected device

### Monochrome Design System

The interface uses a minimalist, academic aesthetic:
- Pure white backgrounds
- Black text and borders
- Light gray highlights for selected items
- Monospace font (Consolas) for a technical appearance
- Flat, borderless design with no decorative elements

## Technical Details

### Network Technologies Used

- **ARP (Address Resolution Protocol)**: Layer 2 network protocol for discovering devices
- **TCP SYN**: Layer 4 protocol for probing device responsiveness
- **TTL Analysis**: Extracting IP header information for OS fingerprinting

### Python Libraries

- **Scapy**: Raw packet creation and manipulation
- **Tkinter**: GUI framework (built-in with Python)
- **Threading**: Background network operations

## Limitations

- Requires root/administrator privileges for raw socket access
- Only scans the local subnet (assumes /24 network)
- TTL-based OS detection is a best guess and may not be 100% accurate
- Some devices may be behind firewalls or have non-standard TTL values

## Troubleshooting

### "Permission Denied" Error
- Run with `sudo` on Linux/macOS
- Run Command Prompt as Administrator on Windows

### "Could not determine local network range"
- Ensure your system is connected to a network
- Check that the network interface is properly configured

### No devices found
- Ensure devices are actually on the network
- Check firewall settings
- Try running the scan again

## Architecture

```
NetOwl/
├── main.py              # Main GUI application
├── network_utils.py     # Network scanning and fingerprinting logic
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Future Enhancements

- Custom network range input
- Export results to CSV/JSON
- Device name resolution via DNS/mDNS
- Service detection on discovered devices
- Scan scheduling and monitoring
- Device information caching

## License

Educational software for learning about network scanning and OS fingerprinting.

## Disclaimer

This application performs network reconnaissance. Only scan networks you own or have permission to scan. Unauthorized network scanning may violate laws in your jurisdiction.
