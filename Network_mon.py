from datetime import datetime, timedelta
from collections import defaultdict

# Ändra till rätt filnamn och kodning om det behövs
with open("network_traffic.log", encoding="utf-16") as file:
    lines = [line.strip() for line in file if line.strip()]

# Omvandla loggarna till listor med rätt datatyper
logs = []
for line in lines:
    try:
        t, src, dst, port, proto = [x.strip() for x in line.split(",")]
        logs.append((datetime.strptime(t, "%Y-%m-%d %H:%M:%S"), src, dst, int(port), proto))
    except ValueError as e:
        print(f"Hoppar över felaktig rad: {line} ({e})")

# Sortera loggar efter tid
logs.sort()

# Dela upp i 5-minutersintervall
interval_start = logs[0][0]
interval_end = interval_start + timedelta(minutes=5)

i = 0
while i < len(logs):
    current_interval = []
    while i < len(logs) and logs[i][0] < interval_end:
        current_interval.append(logs[i])
        i += 1

    print(f"\nAnalyserar intervall {interval_start} till {interval_end} ({len(current_interval)} loggar)")

    # Räkna IP-anslutningar
    ip_counts = defaultdict(int)
    port_warnings = []
    single_dest_counts = defaultdict(lambda: defaultdict(int))

    for log in current_interval:
        t, src, dst, port, proto = log
        ip_counts[src] += 1

        # Ovanliga portar < 1024 utanför 22, 80, 443
        if port < 1024 and port not in [22, 80, 443]:
            port_warnings.append((src, port))

        # Spåra volym mot enstaka destination
        single_dest_counts[src][dst] += 1

    # 1. IP med >100 anslutningar
    for ip, count in ip_counts.items():
        if count > 100:
            print(f"[ALERT] IP {ip} har {count} anslutningar inom 5 min!")

    # 2. IP som använder ovanliga portar
    for src, port in port_warnings:
        print(f"[WARNING] IP {src} använde ovanlig port: {port}")

    # 3. IP som skickar hög volym till en enskild destination
    for src, destinations in single_dest_counts.items():
        for dst, count in destinations.items():
            if count > 50:
                print(f"[NOTICE] IP {src} skickade {count} paket till {dst}")

    # Gå vidare till nästa 5-minutersintervall
    if i < len(logs):
        interval_start = interval_end
        interval_end = interval_start + timedelta(minutes=5)
