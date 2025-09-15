import os
import time
import socket
import struct
from datetime import datetime
from bcc import BPF

# --- Configuration ---
# Configured for your public-facing interface.
IFACE = "eth0"

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "events.log")
ARCHIVE_DIR = os.path.join(LOG_DIR, "archive")

os.makedirs(ARCHIVE_DIR, exist_ok=True)

def rotate_log():
    """Archives the current log file if it exists."""
    if not os.path.exists(LOG_FILE):
        return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archived_file = os.path.join(ARCHIVE_DIR, f"events_{timestamp}.log")
        os.rename(LOG_FILE, archived_file)
        print(f"[*] Log file archived to {archived_file}")
    except OSError as e:
        print(f"[!] Error rotating log file: {e}")

try:
    b = BPF(src_file="xdp_ddos.c")
    fn = b.load_func("xdp_ddos_prog", BPF.XDP)
except Exception as e:
    print(f"Failed to compile or load BPF program: {e}")
    exit(1)

try:
    print(f"[*] Attaching XDP program to interface {IFACE}...")
    b.attach_xdp(IFACE, fn, 0)
except Exception as e:
    print(f"[!] Failed to attach XDP program: {e}")
    print("[!] Check if the interface exists and you are running with sudo privileges.")
    exit(1)

def print_event(cpu, data, size):
    """Callback function to process events from the BPF ring buffer."""
    event = b["events"].event(data)
    ip_addr = socket.inet_ntoa(struct.pack("I", event.saddr))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} - BLOCKED - IP: {ip_addr}, Packets: {event.packet_count}\n"
    print(log_entry.strip())

    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

b["events"].open_ring_buffer(print_event)

print(f"[*] Watching for events on {IFACE}... Press Ctrl+C to exit.")

last_rotation_time = time.time()
SECONDS_IN_A_DAY = 24 * 60 * 60

try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.5)
        if time.time() - last_rotation_time > SECONDS_IN_A_DAY:
            rotate_log()
            last_rotation_time = time.time()
except KeyboardInterrupt:
    print("\n[*] Detaching XDP program...")
finally:
    b.remove_xdp(IFACE, 0)
    print("[*] Program detached. Exiting.")