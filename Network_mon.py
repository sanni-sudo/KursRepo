import pandas as pd
import subprocess
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

LOG_FILE = 'network_traffic.log'
REPORT_FILE = 'attack_report.csv'
UNUSUAL_PORTS_LOG = 'unusual_ports.log'
ADMIN_EMAIL = 'admin@example.com'
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 587
SMTP_USER = 'your_smtp_username'
SMTP_PASSWORD = 'your_smtp_password'

def load_log():
    try:
        df = pd.read_csv(LOG_FILE, names=['timestamp', 'src_ip', 'dst_ip', 'port', 'protocol'], encoding='utf-16')
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        print(f"Fel vid läsning av loggfil: {e}")
        return pd.DataFrame()
    
def empty_log_file(log_file_path):
    try:
        with open(log_file_path, 'w') as f:
            f.truncate(0)  # Tömmer filen
        print(f"{log_file_path} har tömts.")
    except PermissionError:
        print(f"Behörighetsproblem med att tömma {log_file_path}. Försök köra som root.")
    except Exception as e:
        print(f"Fel vid tömning av {log_file_path}: {str(e)}")

def analyze_traffic(df_block):
    flagged_ips = set()
    unusual_ports_info = {}

    # Antal anslutningar per källa-IP
    connection_counts = df_block['src_ip'].value_counts()
    for ip, count in connection_counts.items():
        if count > 100:
            flagged_ips.add(ip)

    # Kontrollera ovanliga portar
    standard_ports = {22, 80, 443}
    unusual = df_block[df_block['port'] < 1024]
    unusual = unusual[~unusual['port'].isin(standard_ports)]

    for ip in unusual['src_ip'].unique():
        flagged_ips.add(ip)
        triggered_ports = unusual[unusual['src_ip'] == ip]['port'].unique().tolist()
        unusual_ports_info[ip] = triggered_ports

    return flagged_ips, unusual_ports_info

def block_ip(ip):
    try:
        # För Windows: använd netsh för att blockera IP
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Block IP"', 'dir=in', 'action=block', 'remoteip=' + ip], check=True)
        print(f"Blockerade IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Fel vid blockering av {ip}: {e}")
    except FileNotFoundError:
        print("netsh är inte tillgängligt. Kontrollera om du har administratörsrättigheter.")

def send_alert(ip_list):
    try:
        body = "Misstänkta IP-adresser:\n" + "\n".join(ip_list)
        msg = MIMEText(body)
        msg['Subject'] = 'Varning: Misstänkt nätverkstrafik'
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ADMIN_EMAIL, msg.as_string())

        print(f"Skickade e-postvarning för IPs: {ip_list}")
    except Exception as e:
        print(f"Fel vid e-postutskick: {e}")

def generate_report(flagged_ips, unusual_ports_info, block_start):
    with open(REPORT_FILE, 'a') as f:
        for ip in flagged_ips:
            ports = unusual_ports_info.get(ip, [])
            ports_str = ",".join(map(str, ports)) if ports else "None"
            # Lägg till detaljer för varje blockering i CSV
            f.write(f"{block_start},{ip},{ports_str},Flaggad pga för många anslutningar/ovanliga portar\n")

def log_unusual_ports(unusual_ports_info, block_start):
    with open(UNUSUAL_PORTS_LOG, 'a') as f:
        for ip, ports in unusual_ports_info.items():
            # Detaljerad logg för ovanliga portar
            f.write(f"{block_start} - IP: {ip} triggade ovanliga portar: {ports}. Misstänkt aktivitet\n")

def main():
    empty_log_file(LOG_FILE)
    empty_log_file(REPORT_FILE)
    df = load_log()
    if df.empty:
        print("Ingen data att analysera.")
        return

    # Sortera på tid
    df = df.sort_values('timestamp')

    # Dela upp i 5-minutersintervall
    start_time = df['timestamp'].min()
    end_time = df['timestamp'].max()
    current_time = start_time

    while current_time <= end_time:
        block_end = current_time + timedelta(minutes=5)
        df_block = df[(df['timestamp'] >= current_time) & (df['timestamp'] < block_end)]

        if not df_block.empty:
            flagged_ips, unusual_ports_info = analyze_traffic(df_block)

            if flagged_ips:
                #send_alert(list(flagged_ips))
                for ip in flagged_ips:
                    block_ip(ip)

                generate_report(flagged_ips, unusual_ports_info, current_time)
                log_unusual_ports(unusual_ports_info, current_time)

        current_time = block_end

if __name__ == "__main__":
    main()
