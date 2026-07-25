from email.message import EmailMessage
import smtplib

msg = EmailMessage()
msg.set_content("This is a test email sent from Python.")
msg['Subject'] = "URGENT: Device Compromise Detected—Immediate Attention Required"
msg['From'] = "REDACTED"
msg['To'] = "REDACTED"


host = "REDACTED"
port = REDACTED


try:
    with smtplib.SMTP(host, port) as server:
        server.send_message(msg)
        print("Email sent successfully.")
except Exception as e:
    print(f"Failed to send email: {e}")

