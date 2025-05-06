import time
import random
from datetime import datetime

LOG_FILE = "/home/testkali/KursRepo/Test_Monitor_Dir/network_traffic.log"

# IP-pooler
frequent_src_ip = "192.168.1.100"        # En IP som skickar mycket trafik
frequent_dest_ip = "10.0.0.5"            # En IP som får mycket trafik

# Protokoll
protocols = ["TCP", "UDP"]

# Funktion för att generera en slumpmässig IP
def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# Generera en loggrad
def generate_log_line():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 30% chans att använda "tung trafik"-IP:er
    if random.random() < 0.3:
        src_ip = frequent_src_ip
    else:
        src_ip = random_ip()

    if random.random() < 0.3:
        dest_ip = frequent_dest_ip
    else:
        dest_ip = random_ip()

    port = random.randint(1, 1023)
    protocol = random.choice(protocols)
    
    return f"{now}, {src_ip}, {dest_ip}, {port}, {protocol}"

# Skapa och fyll loggfilen i max 15 minuter
def main():
    open(LOG_FILE, "w").close()
    print("Startar logggenerering i 30 minuter...")
    print(f"Stattid:", datetime.now())
    start_time = time.time()
    end_time = start_time + 30 * 60  # 15 minuter = 900 sekunder

    with open(LOG_FILE, "a") as log_file:
        while time.time() < end_time:
            line = generate_log_line()
            log_file.write(line + "\n")
            log_file.flush()
            time.sleep(0.5)  # 4 rader per sekund ≈ 1800 rader totalt

    print("Logggenerering avslutad efter 30 minuter.")

if __name__ == "__main__":
    main()
