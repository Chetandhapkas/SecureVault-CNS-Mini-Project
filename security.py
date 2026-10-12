
import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuration
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 600_000


def derive_key(password, salt):
    """Convert a password into a secure encryption key."""
    if not password:
        raise ValueError("Password cannot be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data, password):
    """Encrypt bytes using AES-GCM."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aad = b"SecureVault-v1"
    ciphertext = AESGCM(key).encrypt(nonce, data, aad)

    package = {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

    return json.dumps(package).encode("utf-8")


def decrypt_data(encrypted_data, password):
    """Decrypt data and reject incorrect passwords or tampering."""
    try:
        package = json.loads(encrypted_data.decode("utf-8"))

        if package.get("version") != 1:
            raise ValueError("Unsupported file version.")

        salt = base64.b64decode(package["salt"], validate=True)
        nonce = base64.b64decode(package["nonce"], validate=True)
        ciphertext = base64.b64decode(
            package["ciphertext"], validate=True
        )

        if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE:
            raise ValueError("Invalid encrypted file.")

        key = derive_key(password, salt)

        return AESGCM(key).decrypt(
            nonce, ciphertext, b"SecureVault-v1"
        )

    except Exception as exc:
        raise ValueError(
            "Decryption failed. Check your password and encrypted file."
        ) from exc


def calculate_sha256(data):
    """Calculate the SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()


def check_password_strength(password):
    """Provide basic password-strength feedback."""
    if not password:
        return {
            "score": 0,
            "strength": "Empty",
            "suggestions": ["Enter a password."]
        }

    score = 0
    suggestions = []

    checks = [
        (len(password) >= 8, "Use at least 8 characters."),
        (len(password) >= 12, "Consider using 12 or more characters."),
        (any(c.islower() for c in password), "Add a lowercase letter."),
        (any(c.isupper() for c in password), "Add an uppercase letter."),
        (any(c.isdigit() for c in password), "Add a number."),
        (any(not c.isalnum() for c in password),
         "Consider adding a special character."),
    ]

    for passed, suggestion in checks:
        if passed:
            score += 1
        else:
            suggestions.append(suggestion)

    common = {
        "password", "password123", "12345678",
        "qwerty123", "admin123"
    }

    if password.lower() in common:
        score = 0
        suggestions.append("Avoid common passwords.")

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"

    return {
        "score": score,
        "strength": strength,
        "suggestions": suggestions
    }
