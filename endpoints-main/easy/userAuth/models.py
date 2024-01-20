from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.crypto import get_random_string

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.username

    def generate_email_verification_token(self):
        # Generate a unique token for email verification
        return get_random_string(length=32)

    def save(self, *args, **kwargs):
        # Override save method to generate and set the email_verification_token
        if not self.email_verification_token:
            self.email_verification_token = self.generate_email_verification_token()
        super().save(*args, **kwargs)
