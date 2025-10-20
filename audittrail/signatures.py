"""
Digital signature module for audit trail entries.
Provides non-repudiation through asymmetric cryptography (RSA).
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# Key storage paths
KEYS_DIR = os.path.expanduser("~/.audittrail_keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")
KEY_METADATA_PATH = os.path.join(KEYS_DIR, "key_metadata.json")


def ensure_keys_directory():
    """Ensure the keys directory exists with proper permissions."""
    Path(KEYS_DIR).mkdir(mode=0o700, exist_ok=True)


def generate_keypair(key_size=2048, password=None):
    """
    Generate a new RSA keypair for signing audit entries.
    
    Args:
        key_size: Key size in bits (2048 or 4096 recommended)
        password: Optional password to encrypt private key
    
    Returns:
        Tuple of (private_key, public_key)
    """
    ensure_keys_directory()
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Generate public key
    public_key = private_key.public_key()
    
    # Determine encryption for private key
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption_algorithm = serialization.NoEncryption()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save keys
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_pem)
    os.chmod(PRIVATE_KEY_PATH, 0o600)
    
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_pem)
    os.chmod(PUBLIC_KEY_PATH, 0o644)
    
    # Save metadata
    metadata = {
        "key_size": key_size,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "RSA",
        "encrypted": password is not None
    }
    with open(KEY_METADATA_PATH, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    return private_key, public_key


def load_private_key(password=None):
    """Load the private key from disk."""
    if not os.path.exists(PRIVATE_KEY_PATH):
        raise FileNotFoundError("Private key not found. Run initialize_signing_keys() first.")
    
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_pem = f.read()
    
    if password:
        password_bytes = password.encode()
    else:
        password_bytes = None
    
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=password_bytes,
        backend=default_backend()
    )
    
    return private_key


def load_public_key():
    """Load the public key from disk."""
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise FileNotFoundError("Public key not found. Run initialize_signing_keys() first.")
    
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        public_pem = f.read()
    
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    
    return public_key


def sign_data(data, password=None):
    """
    Sign data with the private key.
    
    Args:
        data: Data to sign (string or bytes)
        password: Optional password if private key is encrypted
    
    Returns:
        Base64-encoded signature
    """
    import base64
    
    if isinstance(data, str):
        data = data.encode()
    
    private_key = load_private_key(password)
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()


def verify_signature(data, signature_b64, public_key=None):
    """
    Verify a signature against data.
    
    Args:
        data: Original data (string or bytes)
        signature_b64: Base64-encoded signature
        public_key: Public key to use (or load from disk)
    
    Returns:
        True if signature is valid, False otherwise
    """
    import base64
    
    if isinstance(data, str):
        data = data.encode()
    
    if public_key is None:
        public_key = load_public_key()
    
    signature = base64.b64decode(signature_b64)
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def initialize_signing_keys(password=None, key_size=2048, force=False):
    """
    Initialize signing keys for the audit trail.
    
    Args:
        password: Optional password to encrypt private key
        key_size: RSA key size (2048 or 4096)
        force: Regenerate keys even if they exist
    
    Returns:
        True if keys were generated, False if they already existed
    """
    if os.path.exists(PRIVATE_KEY_PATH) and not force:
        return False
    
    generate_keypair(key_size, password)
    return True


def get_key_metadata():
    """Get metadata about the current signing keys."""
    if not os.path.exists(KEY_METADATA_PATH):
        return None
    
    with open(KEY_METADATA_PATH, 'r') as f:
        return json.load(f)


def export_public_key():
    """Export the public key as PEM string for sharing."""
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        return f.read().decode()


def sign_entry(entry_data):
    """
    Sign an audit entry.
    
    Args:
        entry_data: Dictionary of entry data
    
    Returns:
        Base64-encoded signature
    """
    # Create deterministic string from entry
    entry_str = json.dumps(entry_data, sort_keys=True)
    return sign_data(entry_str)


def verify_entry_signature(entry_data, signature):
    """
    Verify an audit entry signature.
    
    Args:
        entry_data: Dictionary of entry data
        signature: Base64-encoded signature
    
    Returns:
        True if valid, False otherwise
    """
    entry_str = json.dumps(entry_data, sort_keys=True)
    return verify_signature(entry_str, signature)

