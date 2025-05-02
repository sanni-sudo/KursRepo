import random
from datetime import datetime, timedelta

log_file = "network_traffic.log"

protocols = ["TCP", "UDP"]
common_ports = [22, 80, 443]
unusual_ports = [21, 23, 25, 110, 135, 139, 445, 512]
destination_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
start_time = datetime.now()

def generate_ip(base="10.0.0."):
    return base + str(random.randint(1, 254))

with open(log_file, "w") as f:
    minutes = 12
    total_seconds = minutes * 60

    # 1. ip_high_conn: 1 anslutning var 2 sekunder => 360 rader
    ip_high_conn = generate_ip()
    for i in range(total_seconds // 2):
        timestamp = (start_time + timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S")
        dest_ip = random.choice(destination_ips)
        port = random.choice(common_ports)
        protocol = random.choice(protocols)
        f.write(f"{timestamp}, {ip_high_conn}, {dest_ip}, {port}, {protocol}\n")

    # 2. target_ip: många anslutningar till samma IP från olika källor (var 2 sekunder)
    target_ip = "192.168.1.200"
    for i in range(total_seconds // 2):
        timestamp = (start_time + timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S")
        src_ip = generate_ip()
        port = random.choice(common_ports)
        protocol = random.choice(protocols)
        f.write(f"{timestamp}, {src_ip}, {target_ip}, {port}, {protocol}\n")

    # 3. ip_weird_ports: 1 var 20:e sekund => 36 poster
    ip_weird_ports = generate_ip()
    for i in range(total_seconds // 20):
        timestamp = (start_time + timedelta(seconds=i * 20)).strftime("%Y-%m-%d %H:%M:%S")
        dest_ip = random.choice(destination_ips)
        port = random.choice(unusual_ports)
        protocol = random.choice(protocols)
        f.write(f"{timestamp}, {ip_weird_ports}, {dest_ip}, {port}, {protocol}\n")

    # 4. Legitima: var 12:e sekund => 60 poster
    for i in range(total_seconds // 12):
        timestamp = (start_time + timedelta(seconds=i * 12)).strftime("%Y-%m-%d %H:%M:%S")
        src_ip = generate_ip()
        dest_ip = random.choice(destination_ips)
        port = random.choice(common_ports)
        protocol = random.choice(protocols)
        f.write(f"{timestamp}, {src_ip}, {dest_ip}, {port}, {protocol}\n")

print(f"✅ Skapade loggfilen '{log_file}' med trafik över 12 minuter och garanterade attacker.")
