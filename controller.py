import os
import time
import socket
import struct
import asyncio
import threading
import ctypes
from datetime import datetime
from bcc import BPF
from dotenv import load_dotenv
import telegram

# --- Load Environment Variables ---
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- Configuration ---
IFACE = "eth0"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "events.log")
ARCHIVE_DIR = os.path.join(LOG_DIR, "archive")

os.makedirs(ARCHIVE_DIR, exist_ok=True)

# --- Telegram Bot Initialization ---
bot = None
if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
        print("[*] Telegram bot initialized successfully.")
    except Exception as e:
        print(f"[!] Warning: Could not initialize Telegram bot. Alerts will be disabled. Error: {e}")
else:
    print("[!] Warning: Telegram credentials not found in .env file. Alerts will be disabled.")

def send_telegram_alert(ip_addr, packet_count):
    if not bot: return
    async def send_async():
        try:
            message = (
                f"🚨 **DDoS Attack Mitigated** 🚨\n\n"
                f"Blocked IP Address: `{ip_addr}`\n"
                f"Reason: Exceeded packet threshold\n"
                f"Packet Count at Block: `{packet_count}`\n"
                f"Timestamp: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
            )
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='Markdown')
            print(f"[*] Telegram alert sent for IP: {ip_addr}")
        except Exception as e:
            print(f"[!] Failed to send Telegram alert: {e}")
    try: asyncio.run(send_async())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_async())

# --- BPF Program Loading ---
try:
    print("[*] Compiling and loading BPF program...")
    b = BPF(src_file="xdp_ddos.c", cflags=["-Wno-macro-redefined"])
    fn = b.load_func("xdp_ddos_prog", BPF.XDP)
    print(f"[*] Attaching XDP program to interface {IFACE}...")
    b.attach_xdp(IFACE, fn, 0)
except Exception as e:
    print(f"Failed to initialize BPF: {e}")
    exit(1)

# --- BPF Map Management Functions ---
def ip_to_key(ip_str, bpf_map):
    """
    (FIXED) Converts an IP address string to the key format for a specific BPF map.
    """
    ip_bytes = socket.inet_aton(ip_str)
    ip_int = struct.unpack("I", ip_bytes)[0]
    # Creates a key structure specifically for the provided map.
    return bpf_map.Key(ip_int)

def manage_ip_list(map_name, action, ip_str):
    """Adds or removes an IP from the specified BPF map."""
    try:
        bpf_map = b.get_table(map_name)
        # Pass the map object to ip_to_key to get the correct key type
        key = ip_to_key(ip_str, bpf_map)
        if action == "add":
            bpf_map[key] = ctypes.c_uint32(1)
            print(f"[+] {ip_str} added to {map_name}.")
        elif action == "remove":
            del bpf_map[key]
            print(f"[-] {ip_str} removed from {map_name}.")
    except KeyError:
        print(f"[!] IP {ip_str} not found in {map_name}.")
    except Exception as e:
        print(f"[!] Error managing IP {ip_str}: {e}")

def list_ips(map_name):
    """Prints all IPs currently in the specified BPF map."""
    try:
        bpf_map = b.get_table(map_name)
        if not bpf_map.items():
            print(f"[*] {map_name} is empty.")
            return
        print(f"--- IPs in {map_name} ---")
        for key, _ in bpf_map.items():
            # The key object returned from iteration is the struct itself.
            ip_addr = socket.inet_ntoa(struct.pack("I", key.saddr))
            print(f"  - {ip_addr}")
    except Exception as e:
        print(f"[!] Error listing IPs: {e}")

# --- Event Processing ---
def print_event(cpu, data, size):
    """Callback function to process events from the BPF ring buffer."""
    event = b["events"].event(data)
    ip_addr = socket.inet_ntoa(struct.pack("I", event.saddr))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - AUTO-BLOCKED - IP: {ip_addr}, Packets: {event.packet_count}\n"
    print(f"\n{log_entry.strip()}")
    send_telegram_alert(ip_addr, event.packet_count)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

b["events"].open_ring_buffer(print_event)

def bpf_event_loop():
    """The main loop to poll for BPF events."""
    while True:
        try:
            b.ring_buffer_poll()
            time.sleep(0.5)
        except KeyboardInterrupt:
            break

# --- Main Interactive Shell ---
def print_help():
    print("\n--- Interactive DDoS Mitigation Controller ---")
    print("Commands:")
    print("  wl add <ip>         - Add an IP to the whitelist")
    print("  wl remove <ip>      - Remove an IP from the whitelist")
    print("  wl list             - Show all IPs in the whitelist")
    print("  bl add <ip>         - Manually block an IP")
    print("  bl remove <ip>      - Manually unblock an IP")
    print("  bl list             - Show all manually blocked IPs")
    print("  help                - Show this help message")
    print("  exit                - Detach program and quit")
    print("------------------------------------------")

if __name__ == "__main__":
    event_thread = threading.Thread(target=bpf_event_loop)
    event_thread.daemon = True
    event_thread.start()

    print(f"[*] Watching for events on {IFACE}...")
    print_help()

    try:
        while True:
            cmd_input = input("ddos-ctl> ").strip().lower().split()
            if not cmd_input:
                continue

            command = cmd_input[0]
            if command == "exit":
                break
            elif command == "help":
                print_help()
            elif command in ["wl", "bl"]:
                map_name = "whitelist" if command == "wl" else "manual_blocklist"
                if len(cmd_input) > 1:
                    action = cmd_input[1]
                    if action == "list":
                        list_ips(map_name)
                    elif action in ["add", "remove"] and len(cmd_input) > 2:
                        ip = cmd_input[2]
                        manage_ip_list(map_name, action, ip)
                    else:
                        print("[!] Invalid syntax. Use 'help' for examples.")
                else:
                    print("[!] Invalid syntax. Use 'help' for examples.")
            else:
                print(f"[!] Unknown command: {command}")

    except KeyboardInterrupt:
        print("\n[*] Exiting by user request.")
    finally:
        print("[*] Detaching XDP program...")
        b.remove_xdp(IFACE, 0)
        print("[*] Program detached. Exiting.")