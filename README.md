# XDP DDoS Mitigation System

A high-performance, real-time DDoS mitigation solution using eXpress Data Path (XDP) and BPF for Linux. This system provides automatic detection and blocking of suspicious traffic patterns while offering manual control over IP whitelisting and blocklisting.

## 🌟 Features

- **Real-time Traffic Analysis**: Processes packets at line speed using XDP hook in the Linux kernel
- **Automatic Attack Detection**: Identifies potential DDoS attacks based on packet count thresholds
- **Dynamic Blocklisting**: Automatically blocks malicious IP addresses exceeding configured limits
- **Manual IP Management**: Whitelist trusted IPs and manually block suspicious ones
- **Telegram Integration**: Receive real-time alerts about mitigated attacks
- **Performance-Optimized**: Minimal overhead with efficient BPF hash maps for state tracking

## 🏗️ Architecture

The system consists of two main components:

1. **Kernel Component (XDP Program)**: 
   - Processes every incoming packet at the earliest possible point
   - Maintains flow state using BPF hash maps
   - Implements whitelist/blocklist checks
   - Drops malicious packets before they reach the networking stack

2. **User Space Controller**:
   - Manages BPF maps (whitelist/blocklist operations)
   - Processes events from the kernel
   - Sends alerts via Telegram
   - Provides interactive command interface

## 📋 Prerequisites

- Linux kernel 4.18+ (XDP support required)
- Python 3.7+
- BPF Compiler Collection (BCC)
- hping3 (for testing)
- Telegram Bot Token (optional, for alerts)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/xdp-ddos-mitigation.git
cd xdp-ddos-mitigation
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Set up Telegram alerts (optional):
   - Create a new bot using [BotFather](https://t.me/BotFather)
   - Get your Chat ID
   - Copy `.env.example` to `.env` and add your credentials:
```bash
cp .env.example .env
# Edit .env with your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
```

## 🛠️ Usage

### Starting the System

```bash
# Run the controller (requires sudo)
sudo make run
```

### Interactive Commands

Once the controller is running, use these commands:

```
wl add <ip>         - Add an IP to the whitelist (e.g., wl add 8.8.8.8)
wl remove <ip>      - Remove an IP from the whitelist
wl list             - Show all IPs in the whitelist
bl add <ip>         - Manually block an IP
bl remove <ip>      - Manually unblock an IP
bl list             - Show all manually blocked IPs
help                - Show help message
exit                - Detach program and quit
```

### Testing the System

```bash
# Start a test UDP flood attack (in a separate terminal)
sudo run attack

# Stop the test attack
sudo stop-attack
```

## ⚙️ Configuration

### Packet Threshold

Modify the `PACKET_THRESHOLD` value in `xdp_ddos.c` to adjust sensitivity:

```c
#define PACKET_THRESHOLD 2000  // Adjust based on your traffic patterns
```

### Network Interface

Change the target interface in `controller.py`:

```python
IFACE = "eth0"  # Change to your network interface
```

### Map Sizes

Adjust BPF map capacities in `xdp_ddos.c` based on expected traffic:

```c
BPF_HASH(whitelist, struct flow_key, u32, 1024);  // Whitelist capacity
BPF_HASH(manual_blocklist, struct flow_key, u32, 10240);  // Blocklist capacity
BPF_HASH(flow_map, struct flow_key, struct flow_metrics, 100000);  // Flow tracking
```

## 📊 How It Works

1. **Packet Processing**: Each packet is inspected at the XDP hook point
2. **Whitelist Check**: Whitelisted IPs bypass all further checks
3. **Blocklist Check**: Manually blocked IPs are immediately dropped
4. **Flow Tracking**: Packet counts per source IP are maintained
5. **Threshold Detection**: IPs exceeding the packet threshold are automatically blocked
6. **Alerting**: Block events are logged and Telegram alerts are sent
7. **State Management**: The controller provides management interface

## 🧪 Testing

The included test scripts simulate a UDP flood attack using hping3:

```bash
# Start attack simulation
sudo ./scripts/start_attack.sh

# Monitor blocking in the controller
# Stop attack simulation
sudo ./scripts/stop_attack.sh
```

## 📁 Project Structure

```
xdp-ddos-mitigation/
├── xdp_ddos.c          # Main XDP/BPF program
├── controller.py       # User space controller
├── Makefile           # Build and management commands
├── requirements.txt   # Python dependencies
├── .env.example       # Environment variables template
├── scripts/
│   ├── start_attack.sh # Attack simulation script
│   └── stop_attack.sh  # Attack termination script
└── logs/              # Event log directory (auto-created)
```

## 🔧 Performance Considerations

- The system adds minimal overhead as packets are processed before kernel networking stack
- BPF hash maps are optimized for high-performance lookups/updates
- For 10Gb+ networks, consider CPU pinning and optimizing map sizes
- Monitor system performance when under heavy attack

## ⚠️ Limitations

- Primarily effective against volumetric attacks
- Does not inspect packet contents, only headers
- State is lost on system reboot (persistence can be added)
- IPv6 support would require additional implementation

## 🆘 Troubleshooting

**XDP program fails to load:**
- Verify kernel version supports XDP
- Check interface name is correct

**No events appearing:**
- Confirm network traffic is reaching the interface
- Check threshold value isn't too high

**Telegram alerts not working:**
- Verify .env file contains correct credentials
- Check internet connectivity

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📚 Resources

- [eBPF and XDP Reference Guide](https://cilium.io/learn/)
- [BCC Documentation](https://github.com/iovisor/bcc)
- [XDP Tutorials](https://github.com/xdp-project/xdp-tutorial)

## 🏛️ Academic Reference

This implementation demonstrates practical application of:
- In-kernel networking with XDP
- BPF for high-performance packet processing
- Real-time DDoS mitigation techniques
- Userspace-kernel communication mechanisms

---

**Disclaimer**: This tool is intended for educational and research purposes. Ensure you have proper authorization before testing on any network.