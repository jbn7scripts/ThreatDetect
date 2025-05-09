from app import send_email

if __name__ == "__main__":
    send_email(
        to_email="jabfar872@gmail.com",
        subject="SMTP Debug Test",
        body="If you see this, SMTP is working!"
    )
