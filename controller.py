import sys
import time
import socket
import struct
from bcc import BPF

# Configuration
IFACE = "eth0"  # inside Docker, usually eth0
if len(sys.argv) > 1:
    IFACE = sys.argv[1]

print(f"Attaching XDP program to interface {IFACE}...")

try:
    b = BPF(src_file="xdp_ddos.c")
    fn = b.load_func("xdp_ddos_prog", BPF.XDP)
    b.attach_xdp(IFACE, fn, 0)
except Exception as e:
    print(f"Error attaching XDP program: {e}")
    sys.exit(1)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    source_ip = socket.inet_ntoa(struct.pack("I", event.saddr))
    print(f"[*] DDoS Attack DETECTED from {source_ip} ({event.packet_count} packets)")

b["events"].open_ring_buffer(print_event)
print("XDP program attached. Press Ctrl+C to stop.")

try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\nDetaching XDP program...")
finally:
    b.remove_xdp(IFACE, 0)
    print("Program detached.")
