#!/bin/bash

# Skapat av: Sanna Nilsson, 17 april 2025
# Namn: Ett bash-skript för att automatiskt försöka olika autentiseringar (både lokalt och mot SSH)
# så att rätt loggrader genereras i t.ex. /var/log/auth.log.
# 
# Skapa några loggar för säkerhetstest
echo "Startar loggtest..."

# 1. Försök köra sudo med fel lösenord (genererar: 'authentication failure')
echo "Försöker sudo med fel lösenord..."
echo "wrongpassword" | sudo -S ls 2>/dev/null

# 2. Försök använda su till en ogiltig användare
echo "Försöker su till ogiltig användare..."
echo "wrongpassword" | su invaliduser -c "whoami" 2>/dev/null

# 3. Försök SSH till localhost med ogiltig användare (kräver att SSH är igång)
echo "Försöker SSH till localhost med ogiltig användare..."
sshpass -p "abc123" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 invaliduser@localhost exit
#ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 invaliduser@localhost exit

# 4. Försök SSH till localhost med giltig användare men fel lösenord
echo "Försöker SSH till localhost med giltig användare men fel lösenord..."
sshpass -p "fel_losenord" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $USER@localhost exit

# 5. Valfritt: Lyckad inloggning om du vill skapa 'session opened'
# echo "Försöker SSH med korrekt användare och lösenord..."
# sshpass -p "ratt_losenord" ssh -o StrictHostKeyChecking=no $USER@localhost "echo 'Lyckad inloggning'"

echo "Loggtest färdigt. Kontrollera /var/log/auth.log"