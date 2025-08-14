import os
import smtplib
from Storage import Storage


class SendEmail:
    def __init__(self):
        self.connection = smtplib.SMTP('smtp.gmail.com', 587)
        self.connection.starttls()
        self.connection.login(user=os.environ.get("MY_EMAIL"), password=os.environ.get("PASS"))

    def send_email(self, user_email, code):
        email_body = f"Subject: Verification Code\n\nCode: {code}.\n\nHave a nice day!"
        self.connection.sendmail(from_addr=os.environ.get("MY_EMAIL"), to_addrs=user_email, msg=email_body)
        self.connection.quit()