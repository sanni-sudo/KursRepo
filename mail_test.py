import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr

EMAIL_FROM = "testkali@localhost"
EMAIL_TO = "testkali@localhost"

try:
    msg = MIMEText("Detta är ett test från Python med åäö", "plain", "utf-8")
    msg["From"] = formataddr((str(Header("Python Test", "utf-8")), EMAIL_FROM))
    msg["To"] = EMAIL_TO
    msg["Subject"] = Header("Testmeddelande från Python", "utf-8")

    server = smtplib.SMTP("localhost", 25)
    server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
    server.quit()

    print("E-post skickat!")
except Exception as e:
    print("Fel vid sändning:", str(e))