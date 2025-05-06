import csv
import time
import smtplib
import subprocess
from email.mime.text import MIMEText
from datetime import datetime

# Konfigurationer
LOG_FILE = "Test_Monitor_Dir/network_traffic.log"
CSV_FILE = "Test_Monitor_Dir/attack_report_test.csv"
EMAIL_RECIPIENT = "testkali@localhost"
UFW_BLOCK_COMMAND = "sudo ufw deny from {}"

# Anslutning och portregler
MAX_CONNECTIONS = 100  # Exempel för att flagga om anslutningar > 100
UNUSUAL_PORTS = {21, 22, 80, 443}  # Vanliga portar som vi inte vill flagga

# För att hålla reda på e-posttidsintervall
last_email_sent_time = time.time()

# Funktion för att läsa loggfilen
def read_log_file():
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)  # Gå till slutet av filen
        while True:
            line = file.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)  # Vänta innan vi försöker läsa på nytt

# Funktion för att skicka e-post
def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "testkali@testkalilinuxcl-2.labb.local"
    msg["To"] = EMAIL_RECIPIENT

    try:
        with smtplib.SMTP("localhost") as server:
            server.sendmail("testkali@testkalilinuxcl-2.labb.local", EMAIL_RECIPIENT, msg.as_string())

    except Exception as e:
        print(f"[ERROR] Misslyckades med att skicka e-post: {e}")

# Funktion för att analysera loggposter och flagga misstänkta IP
def analyze_log(line):
    try:
        timestamp, src_ip, dest_ip, port, protocol = line.split(",")
        port = int(port.strip())
        timestamp = timestamp.strip()
        issue = ""

        # Flagga för ovanlig port
        if port not in UNUSUAL_PORTS:
            issue = "Ovanlig port"
        
        # Flagga för många anslutningar
        if count_connections(src_ip) > MAX_CONNECTIONS:
            issue += " + Många anslutningar (>100)"

        # Om ett problem upptäcks, skriv till CSV
        if issue:
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            end_time = start_time  # Enklare att sätta samma tid för start/slut
            write_to_csv(start_time, end_time, src_ip, 1, issue)
            return src_ip, issue  # Returnera IP och problem

    except ValueError:
        print(f"[DEBUG] Ogiltig rad hoppar över: {line}")
        return None

# Skriv till CSV
def write_to_csv(start_time, end_time, ip, count, issue):
    with open(CSV_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([start_time, end_time, ip, count, issue])

# Funktion för att skicka sammanfattning av attacker via e-post
def send_summary_email(attacks):
    if not attacks:
        return
    
    body = "Sammanfattning av attacker:\n\n"
    for attack in attacks:
        body += f"IP: {attack[0]}, Orsak: {attack[1]}\n"
    
    send_email("Sammanfattning av misstänkta attacker", body)

# Blockera IP med UFW
def block_ip_with_ufw(ip):
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if ip in result.stdout:
            print(f"[INFO] IP {ip} är redan blockerat.")
            return

        print(f"[INFO] Blockerar IP: {ip} med UFW...")
        subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Misslyckades med att blockera IP {ip}: {e}")


# Funktion för att räkna anslutningar per IP
def count_connections(ip):
    # Exempel på att räkna anslutningar från loggen
    count = 0
    with open(LOG_FILE, "r") as log_file:
        for line in log_file:
            if ip in line:
                count += 1
    return count

# Huvudloop
def main():
    global last_email_sent_time
    flagged_ips = []

    print("Startar loggövervakning...")
    for log_line in read_log_file():
        print(f"[DEBUG] Läser rad: {log_line}")
        result = analyze_log(log_line)
        if result:
            flagged_ips.append(result)

        # Kontrollera om det har gått 5 minuter sedan senaste e-post
        if time.time() - last_email_sent_time > 5 * 60:
            send_summary_email(flagged_ips)  # Skicka sammanfattning av attacker
            flagged_ips.clear()  # Töm listan efter att e-post har skickats
            last_email_sent_time = time.time()  # Uppdatera e-posttidsstämpeln

        # Blockera IP-adresser som har mer än 100 anslutningar
        for ip, issue in flagged_ips:
            if count_connections(ip) > MAX_CONNECTIONS:
                block_ip_with_ufw(ip)  # Blockera IP med UFW

if __name__ == "__main__":
    with open(LOG_FILE, "w") as file:
        pass  # Öppna filen i skrivläge och stäng den direkt för att rensa innehållet
    subprocess.Popen(["python","log_gen.py"])
    main()
