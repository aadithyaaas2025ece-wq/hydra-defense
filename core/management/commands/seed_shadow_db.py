"""
Management command: python manage.py seed_shadow_db
Seeds the Shadow Database with realistic fake (poison) data.
Run this once after first migration.
"""

from django.core.management.base import BaseCommand
from core.models import UserProfile
from ai_agents.honeypot import generate_fake_users
import logging

logger = logging.getLogger('hydra')


class Command(BaseCommand):
    help = 'Seeds the Shadow Database with poison data to trap attackers'

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=50, help='Number of fake users to create')
        parser.add_argument('--real', action='store_true', help='Also seed real DB with sample data')

    def handle(self, *args, **options):
        count = options['count']
        self.stdout.write(f"🐍 Hydra: Seeding Shadow DB with {count} poison user profiles...")

        fake_users = generate_fake_users(count)
        created = 0

        for fake in fake_users:
            try:
                UserProfile.objects.using('shadow').get_or_create(
                    email=fake['email'],
                    defaults={
                        'display_name': f"{fake['first_name']} {fake['last_name']}",
                        'bio': f"Account holder since {fake['date_joined'][:10]}",
                        'location': 'United States',
                    }
                )
                created += 1
            except Exception as e:
                self.stderr.write(f"Error creating record: {e}")

        self.stdout.write(self.style.SUCCESS(
            f"✅ Shadow DB seeded: {created} poison profiles ready to trap attackers!"
        ))

        if options['real']:
            self.stdout.write("Seeding real DB with sample data...")
            real_users = [
                ('Alice Johnson', 'alice@example.com', 'Software engineer', 'San Francisco'),
                ('Bob Smith', 'bob@example.com', 'Product manager', 'New York'),
                ('Carol Williams', 'carol@example.com', 'Designer', 'London'),
            ]
            for name, email, bio, loc in real_users:
                UserProfile.objects.using('default').get_or_create(
                    email=email,
                    defaults={'display_name': name, 'bio': bio, 'location': loc}
                )
            self.stdout.write(self.style.SUCCESS("✅ Real DB seeded with sample data."))
