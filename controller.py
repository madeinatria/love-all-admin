from __future__ import print_function
import uuid
from config import atria_email, atria_password
import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def generate_card_number():
    card_uuid = uuid.uuid4()
    card_number = int(str(card_uuid).replace('-', '')[:16], 16)
    return card_number





import base64
import os.path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

def sendEmailToMerchant(email, password, merchantname, username):
    sender_email = atria_email
    recipient_email = email

    message = MIMEMultipart('related')
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Subject'] = 'Welcome to LoveAll Loyalty Program'

    with open(os.path.join(os.path.dirname(__file__), 'email_templates/merchant.html'), 'r') as f:
        html = f.read()

    html = html.replace("{{username}}", username)
    html = html.replace("{{useremail}}", email)
    html = html.replace("{{userpassword}}", password)
    html = html.replace("{{merchantname}}", merchantname)

    html_content = MIMEText(html, 'html')
    message.attach(html_content)

    creds, _ = google.auth.default()

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
        send_message = (service.users().messages().send(userId="me", body=message).execute())
        print(F'sent message to {recipient_email} Message Id: {send_message["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    return send_message


#sendEmailToMerchant("lakshaykumar.coder@gmail.com","djhru","ffw","hdjh")
