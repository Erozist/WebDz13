from pathlib import Path
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi_mail.errors import ConnectionErrors
from pydantic import BaseModel, EmailStr
from typing import List
from src.config.settings import settings



class EmailSchema(BaseModel):
    email: List[EmailStr]

conf = ConnectionConfig(
    MAIL_USERNAME=settings.mail_username,
    MAIL_PASSWORD=settings.mail_password,
    MAIL_FROM=settings.mail_from,
    MAIL_PORT=settings.mail_port,
    MAIL_SERVER="smtp.meta.ua",
    MAIL_FROM_NAME="Example email",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=Path(__file__).parent / 'templates',
)



async def send_email(email: EmailSchema, subject: str, body: str):
    try:
        message = MessageSchema(
            subject=subject,
            recipients=email.dict().get("email"),
            body=body,
            subtype="html"
        )
        fm = FastMail(conf)
        await fm.send_message(message)
    except ConnectionErrors as err:
        print(err)
