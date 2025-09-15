import os
import time
import socket
import struct
import asyncio
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
    """Sends a formatted alert message asynchronously to the configured Telegram chat."""
    if not bot:
        return

    # Define an async function to send the message
    async def send_async():
        try:
            # Before sending, start a chat with your bot in Telegram!
            message = (
                f"🚨 **DDoS Attack Mitigated** 🚨\n\n"
                f"Blocked IP Address: `{ip_addr}`\n"
                f"Reason: Exceeded packet threshold\n"
                f"Packet Count at Block: `{packet_count}`\n"
                f"Timestamp: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
            )
            # Await the coroutine to actually send the message
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='Markdown')
            print(f"[*] Telegram alert sent for IP: {ip_addr}")
        except Exception as e:
            print(f"[!] Failed to send Telegram alert: {e}")
            print("[!] Have you started a conversation with your bot yet? Send it /start.")

    # Run the async function from our synchronous context
    try:
        asyncio.run(send_async())
    except RuntimeError:
        # This can happen in some environments, handle it by creating a new loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_async())


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
    # Add cflags to suppress the harmless macro redefinition warnings
    b = BPF(src_file="xdp_ddos.c", cflags=["-Wno-macro-redefined"])
    fn = b.load_func("xdp_ddos_prog", BPF.XDP)
except Exception as e:
    print(f"Failed to compile or load BPF program: {e}")
    exit(1)

try:
    print(f"[*] Attaching XDP program to interface {IFACE}...")
    b.attach_xdp(IFACE, fn, 0)
except Exception as e:
    print(f"[!] Failed to attach XDP program: {e}")
    exit(1)

def print_event(cpu, data, size):
    """Callback function to process events from the BPF ring buffer."""
    event = b["events"].event(data)
    ip_addr = socket.inet_ntoa(struct.pack("I", event.saddr))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} - BLOCKED - IP: {ip_addr}, Packets: {event.packet_count}\n"
    print(log_entry.strip())

    send_telegram_alert(ip_addr, event.packet_count)

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