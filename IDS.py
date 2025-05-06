import csv
import logging
import smtplib
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
import os

LOG_FILE = 'network_traffic.log'
CSV_REPORT = 'attack_report_test.csv'

# Rensa tidigare rapport
open(CSV_REPORT, 'w').close()

# Standard loggning till fil
logging.basicConfig(
    filename=CSV_REPORT,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

def parse_log_line(line):
    try:
        timestamp_str, src_ip, dst_ip, port, protocol = line.strip().split(', ')
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port': int(port),
            'protocol': protocol
        }
    except Exception as e:
        print(f"[WARNING] Ogiltig rad: {line.strip()} ({e})")
        return None

def send_email(subject, message):
    try:
        # Konfiguration (kommenterad tills du har en fungerande server)
        # ...
        pass
    except Exception as e:
        logging.error(f"Kunde inte skicka e-post: {e}")
        print(f"[ERROR] Kunde inte skicka e-post: {e}")

def block_ip(ip):
    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
        msg = f"Blockerat IP med UFW: {ip}"
        logging.info(msg)
        print(f"[INFO] {msg}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Misslyckades att blockera IP {ip}: {e}")
        print(f"[ERROR] Misslyckades att blockera IP {ip}: {e}")

def analyze_traffic(batch):
    src_counter = defaultdict(int)
    dst_counter = defaultdict(lambda: defaultdict(int))
    port_warnings = set()
    flagged_ips = set()

    for entry in batch:
        src = entry['src_ip']
        dst = entry['dst_ip']
        port = entry['port']

        src_counter[src] += 1
        dst_counter[src][dst] += 1

        if port < 1024 and port not in [22, 80, 443]:
            port_warnings.add((src, dst, port))

    for ip, count in src_counter.items():
        if count > 100:
            msg = f"Hög trafik från {ip}: {count} anslutningar"
            logging.warning(msg)
            print(f"[WARNING] {msg}")
            flagged_ips.add(ip)

    for src, dsts in dst_counter.items():
        for dst, count in dsts.items():
            if count > 50:
                msg = f"{src} skickade {count} anslutningar till {dst}"
                logging.warning(msg)
                print(f"[WARNING] {msg}")
                flagged_ips.add(src)

    for src, dst, port in port_warnings:
        msg = f"{src} använde ovanlig port {port} till {dst}"
        logging.warning(msg)
        print(f"[WARNING] {msg}")
        flagged_ips.add(src)

    for ip in flagged_ips:
        send_email(
            "Misstänkt aktivitet",
            f"Flaggat IP: {ip} med misstänkt aktivitet."
        )
        block_ip(ip)

def load_and_process_log():
    if not os.path.exists(LOG_FILE):
        logging.error(f"{LOG_FILE} saknas.")
        print(f"[ERROR] {LOG_FILE} saknas.")
        return

    with open(LOG_FILE, 'r') as f:
        lines = f.readlines()

    log_entries = [parse_log_line(line) for line in lines]
    log_entries = [entry for entry in log_entries if entry]

    if not log_entries:
        print("[INFO] Ingen data att analysera.")
        return

    log_entries.sort(key=lambda x: x['timestamp'])
    start_time = log_entries[0]['timestamp']
    end_time = log_entries[-1]['timestamp']

    window_start = start_time
    while window_start <= end_time:
        window_end = window_start + timedelta(minutes=5)
        batch = [entry for entry in log_entries if window_start <= entry['timestamp'] < window_end]

        if batch:
            logging.info(f"Analyserar trafik från {window_start} till {window_end} ({len(batch)} rader) ")
            print(f"[INFO] Analyserar trafik från {window_start} till {window_end} ({len(batch)} rader)")
            analyze_traffic(batch)

        window_start = window_end

if __name__ == "__main__":
    load_and_process_log()
