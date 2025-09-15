# XDP/eBPF DDoS Mitigation Tool

This project is a simple but effective DDoS mitigation tool using XDP (eXpress Data Path) and eBPF. It is designed to run in the Linux kernel for high-performance packet processing, capable of detecting and blocking IP addresses that send an excessive number of packets.

## Features

-   **High-Performance:** Uses XDP to process packets directly in the network driver, dropping malicious traffic before it hits the kernel's network stack.
-   **Dynamic Blocking:** Automatically identifies and blocks high-volume source IPs based on a configurable packet threshold.
-   **Userspace Monitoring:** A Python controller loads the XDP program and listens for real-time events (e.g., an IP being blocked) via a BPF ring buffer.
-   **Logging:** Records all blocking events to a log file with automatic daily rotation.
-   **Safe by Default:** The default configuration is set to run on the `localhost` interface for safe testing and demonstration.

---

## ⚠️ Important: Responsible Use

This tool is for educational and defensive purposes on networks and servers that you own or have explicit permission to test. **Do not use this tool to attack systems you do not own.** The default settings are configured for safe, local testing to prevent accidental misuse.

---

## Installation (Ubuntu 22.04)

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd <repo-name>
    ```

2.  **Install system dependencies:**
    This will install the eBPF compiler toolchain, kernel headers, Python's BCC library, and the `hping3` traffic generator.
    ```bash
    sudo apt update
    sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) python3-bcc hping3 make
    ```
    
3. **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## How to Use

### Quickstart: Safe Local Testing

This is the recommended way to see the tool in action without affecting any public network traffic.

1.  **Start the Controller:**
    Open a terminal. The `make run` command will start the Python controller, which loads and attaches the XDP program to your local loopback (`lo`) interface.
    ```bash
    sudo make run
    ```
    You will see a message that it is watching for events.

2.  **Start the Test Attack:**
    Open a **second terminal**. The `make attack` command runs a script that floods `127.0.0.1` with UDP packets.
    ```bash
    sudo make attack
    ```

3.  **Observe the Result:**
    In the first terminal, you will immediately see output showing that `127.0.0.1` has been blocked. Events will also be saved in `logs/events.log`.

4.  **Stop the Attack and Controller:**
    -   In the second terminal, press `Ctrl+C` to stop the attack.
    -   In the first terminal, press `Ctrl+C` to stop the controller and detach the XDP program.

### Advanced: Two-Server Testing

To test this in a realistic environment (like the one with your two cloud servers), you need to change the configuration.

**On the Target Server (e.g., `65.109.132.110`):**

1.  Find your public network interface name (e.g., `eth0`) using `ip a`.
2.  Edit `controller.py` and change the `IFACE` variable:
    ```python
    # controller.py
    IFACE = "eth0"  # Change from "lo" to your public interface
    ```
3.  Run the controller: `sudo make run`.

**On the Attacker Server (e.g., `65.108.57.206`):**

1.  Edit `scripts/start_attack.sh` and change the `TARGET` variable:
    ```bash
    # scripts/start_attack.sh
    TARGET="65.109.132.110" # Change from "127.0.0.1" to your target's IP
    ```
2.  Run the attack: `sudo ./scripts/start_attack.sh`.

---

## How It Works

1.  **`xdp_ddos.c` (Kernel Space):** This eBPF program is attached to a network interface. For each incoming IPv4 packet, it increments a counter for the source IP in a BPF hash map. If the count exceeds `PACKET_THRESHOLD`, it drops the packet and sends an event to userspace.
2.  **`controller.py` (User Space):** This script uses the BCC library to compile and load the eBPF program. It attaches it to the specified network interface and listens on a BPF ring buffer for events from the kernel, which it then logs.

## License

This project is licensed under the GPL. See the `LICENSE` string in `xdp_ddos.c`.