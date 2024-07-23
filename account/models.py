from django.db import models
from django.utils import timezone
from datetime import datetime, timedelta 


class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.id:
            self.expires_at = datetime.now() + timedelta(minutes=10)  # OTP valid for 10 minutes
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at

    