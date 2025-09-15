import os
import time
import socket
import struct
from datetime import datetime
from bcc import BPF

# --- Configuration ---
IFACE = "eno1"
ATTACKER_IP = "65.108.57.206"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "events.log")
ARCHIVE_DIR = os.path.join(LOG_DIR, "archive")

os.makedirs(ARCHIVE_DIR, exist_ok=True)

def rotate_log():
    if os.path.exists(LOG_FILE):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archived_file = os.path.join(ARCHIVE_DIR, f"events_{timestamp}.log")
        os.rename(LOG_FILE, archived_file)

print(f"[*] Attaching XDP program to interface {IFACE}...")
b = BPF(src_file="xdp_ddos.c")
fn = b.load_func("xdp_ddos_prog", BPF.XDP)
b.attach_xdp(IFACE, fn, 0)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    ip_addr = socket.inet_ntoa(struct.pack("I", event.saddr))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {ip_addr} - {event.packet_count} packets\n"
    print(log_entry.strip())
    if ip_addr == ATTACKER_IP:
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)

b["events"].open_ring_buffer(print_event)

last_rotation = time.time()

try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.5)
        if time.time() - last_rotation > 24*60*60:
            rotate_log()
            last_rotation = time.time()
except KeyboardInterrupt:
    print("\n[*] Detaching XDP program...")
finally:
    b.remove_xdp(IFACE, 0)
    print("[*] Program detached. Exiting.")
