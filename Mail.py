import os
import smtplib
from Storage import Storage


class SendEmail:
    def __init__(self):
        self.user = os.environ.get("MY_EMAIL")
        self.password = os.environ.get("PASS")

    def send_email(self, user_email, code):
        email_body = f"Subject: Verification Code\n\nCode: {code}.\n\nHave a nice day!"
        with smtplib.SMTP('smtp.gmail.com', 587) as connection:
            connection.starttls()
            connection.login(user=self.user, password=self.password)
            connection.sendmail(from_addr=self.user, to_addrs=user_email, msg=email_body)
