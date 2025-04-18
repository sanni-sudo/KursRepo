#!/bin/bash

# Skapat av: Sanna Nilsson, 17 april 2025
# Namn: Ett bash-skript för att automatisera säkerhetstester där olika autentiseringsförsök
# (både lokalt och via SSH) utförs och detta loggas i /var/log/auth.log.

# Skapa några loggar för säkerhetstest
echo "Startar loggtest..."

# Kör sudo med fel lösenord (genererar: 'authentication failure')
echo "Försöker sudo med fel lösenord..."
echo "wrongpassword" | sudo -S ls 2>/dev/null

# Använder su till en ogiltig användare
echo "Försöker su till ogiltig användare..."
echo "wrongpassword" | su invaliduser -c "whoami" 2>/dev/null

# SSH:a till localhost med ogiltig användare (SSH ska vara aktiverad)
echo "Försöker SSH till localhost med ogiltig användare..."
sshpass -p "abc123" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 invaliduser@localhost exit
#ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 invaliduser@localhost exit

# SSH:a till localhost med giltig användare men fel lösenord
echo "Försöker SSH till localhost med giltig användare men fel lösenord..."
sshpass -p "fel_losenord" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 testkali@localhost exit

# Lyckad inloggning för att skapa 'session opened'
echo "Försöker SSH med korrekt användare (nyckelbaserad inloggning)..."
ssh -o StrictHostKeyChecking=no testkali@localhost "echo 'Lyckad inloggning'"

echo "Loggtest färdigt. Kontrollera /var/log/auth.log"