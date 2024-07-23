
from django.core.mail import send_mail
from django.conf import settings
import random

def generate_otp():
    """
    Generate a random 6-digit OTP.
    Returns Randomly generated OTP.
    """
    return ''.join(random.choices('0123456789', k=6))

def send_otp_email(email, contact_name, otp):
    subject = "Your OTP for Verification"
    message = f"Hi {contact_name},\n\nYour OTP is: {otp}\n\nPlease use this OTP to complete your Verification process.\n\nThank you."
    sender = settings.EMAIL_HOST_USER  # Sender's email address
    recipient_list = [email]
    send_mail(subject, message, sender, recipient_list)