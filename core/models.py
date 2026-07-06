# core/models.py
from django.db import models


class UserProfile(models.Model):
    """Demo model — target for SQL injection attacks in tests."""
    display_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    bio = models.TextField(blank=True)
    location = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.display_name

    class Meta:
        app_label = 'core'
