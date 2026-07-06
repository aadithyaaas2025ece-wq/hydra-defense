"""
HYDRA HONEYPOT DATA GENERATOR
Generates realistic-looking but completely fake data to feed to quarantined attackers.

Hackers who reach the Shadow Realm will see:
- Fake user accounts with valid-looking emails/hashes
- Fake credit card numbers (Luhn-valid but not real)
- Fake API keys and tokens
- Fake internal data that wastes their time

Everything here is 100% synthetic. No real data is ever exposed.
"""

import random
import hashlib
import string
import json
from datetime import datetime, timedelta


def _random_string(length: int, chars=string.ascii_lowercase) -> str:
    return ''.join(random.choices(chars, k=length))


def _random_email() -> str:
    domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
               'protonmail.com', 'icloud.com', 'aol.com']
    name = _random_string(random.randint(4, 10))
    sep = random.choice(['', '.', '_'])
    suffix = _random_string(random.randint(2, 6))
    return f"{name}{sep}{suffix}@{random.choice(domains)}"


def _fake_password_hash() -> str:
    """Generate a bcrypt-looking hash (fake but realistic format)."""
    salt = _random_string(22, string.ascii_letters + string.digits + './+')
    body = _random_string(31, string.ascii_letters + string.digits + './+')
    return f"$2b$12${salt}{body}"


def _luhn_valid_cc() -> str:
    """Generate a Luhn-valid fake credit card number. NOT a real card."""
    # Use test card prefix ranges (these are well-known test numbers, not real)
    prefix = random.choice(['4111111', '5500000', '3714496', '6011000'])
    length = 16
    partial = prefix + ''.join([str(random.randint(0, 9)) for _ in range(length - len(prefix) - 1)])

    # Luhn checksum
    total = 0
    for i, digit in enumerate(reversed(partial)):
        n = int(digit)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    return partial + str(check)


def _fake_api_key() -> str:
    chars = string.ascii_letters + string.digits
    return 'sk-' + _random_string(48, chars)


def _fake_jwt() -> str:
    """Fake JWT token (not valid, but looks real)."""
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = _random_string(80, string.ascii_letters + string.digits + '+/=')
    sig = _random_string(43, string.ascii_letters + string.digits + '-_')
    return f"{header}.{payload}.{sig}"


def generate_fake_users(count: int = 100) -> list[dict]:
    """Generate N fake user records."""
    users = []
    for i in range(count):
        reg_date = datetime.now() - timedelta(days=random.randint(1, 1000))
        users.append({
            'id': i + 1,
            'username': _random_string(random.randint(4, 12)),
            'email': _random_email(),
            'password': _fake_password_hash(),
            'first_name': random.choice(['James', 'Emma', 'Oliver', 'Sophia', 'Liam', 'Ava']),
            'last_name': random.choice(['Smith', 'Johnson', 'Williams', 'Brown', 'Jones']),
            'is_admin': random.random() < 0.05,
            'date_joined': reg_date.isoformat(),
            'last_login': (reg_date + timedelta(days=random.randint(0, 30))).isoformat(),
            'api_key': _fake_api_key(),
        })
    return users


def generate_fake_transactions(count: int = 50) -> list[dict]:
    """Generate fake payment/transaction records."""
    transactions = []
    for i in range(count):
        transactions.append({
            'id': f"txn_{_random_string(16, string.hexdigits.lower())}",
            'amount': round(random.uniform(5, 2000), 2),
            'currency': random.choice(['USD', 'EUR', 'GBP']),
            'card_last4': _luhn_valid_cc()[-4:],
            'card_brand': random.choice(['Visa', 'Mastercard', 'Amex']),
            'status': random.choice(['completed', 'pending', 'failed']),
            'created_at': (datetime.now() - timedelta(hours=random.randint(1, 720))).isoformat(),
        })
    return transactions


def generate_fake_config() -> dict:
    """Fake server configuration to mislead attackers."""
    return {
        'database': {
            'host': f"db-{_random_string(8)}.internal.example.com",
            'port': random.choice([5432, 3306, 27017]),
            'name': 'production_db',
            'user': 'db_admin',
            'password': _random_string(32, string.ascii_letters + string.digits + '!@#$'),
        },
        'redis': {
            'url': f"redis://:{_random_string(20)}@redis.internal:6379/0"
        },
        'secret_key': _fake_api_key(),
        'jwt_secret': _random_string(64, string.ascii_letters + string.digits),
        'smtp': {
            'host': 'smtp.sendgrid.net',
            'api_key': _fake_api_key(),
        },
        'aws': {
            'access_key_id': 'AKIA' + _random_string(16, string.ascii_uppercase + string.digits),
            'secret_access_key': _random_string(40, string.ascii_letters + string.digits + '/+'),
            'region': random.choice(['us-east-1', 'eu-west-1', 'ap-southeast-1']),
        }
    }


# Pre-generate a poison dataset (loaded once, reused)
POISON_DATASET = {
    'users': generate_fake_users(200),
    'transactions': generate_fake_transactions(100),
    'config': generate_fake_config(),
}
