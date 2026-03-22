"""
Key Management Module
=====================
Handles key generation, storage, rotation, and revocation.
Provides secure key lifecycle management.
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA

from .rsa_encryption import RSACipher


class KeyManager:
    """
    Manages RSA key pairs with rotation and revocation support.
    Keys are stored in the filesystem with metadata tracking.
    """

    def __init__(self, keys_dir: str):
        """
        Initialize KeyManager.

        Args:
            keys_dir: Directory to store keys and metadata
        """
        self.keys_dir = keys_dir
        self.metadata_file = os.path.join(keys_dir, 'key_metadata.json')
        os.makedirs(keys_dir, exist_ok=True)
        self._load_metadata()

    def _load_metadata(self):
        """Load key metadata from file."""
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {'keys': {}, 'revoked': []}

    def _save_metadata(self):
        """Save key metadata to file."""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2, default=str)

    def generate_user_keys(self, username: str, key_size: int = 2048) -> dict:
        """
        Generate RSA key pair for a user.

        Args:
            username: The username to generate keys for
            key_size: RSA key size in bits

        Returns:
            dict with 'private_key' and 'public_key' as PEM bytes
        """
        user_dir = os.path.join(self.keys_dir, username)
        os.makedirs(user_dir, exist_ok=True)

        private_path = os.path.join(user_dir, 'private_key.pem')
        public_path = os.path.join(user_dir, 'public_key.pem')

        private_key, public_key = RSACipher.save_keypair(
            private_path, public_path, key_size
        )

        # Compute key fingerprint
        fingerprint = hashlib.sha256(public_key).hexdigest()[:16]

        # Store metadata
        self.metadata['keys'][username] = {
            'fingerprint': fingerprint,
            'created': datetime.utcnow().isoformat(),
            'key_size': key_size,
            'version': self.metadata['keys'].get(username, {}).get('version', 0) + 1,
            'status': 'active',
        }
        self._save_metadata()

        return {
            'private_key': private_key,
            'public_key': public_key,
            'fingerprint': fingerprint,
        }

    def get_public_key(self, username: str) -> bytes:
        """Load a user's public key."""
        if username in self.metadata.get('revoked', []):
            raise ValueError(f"Key for user '{username}' has been revoked")

        public_path = os.path.join(self.keys_dir, username, 'public_key.pem')
        if not os.path.exists(public_path):
            raise FileNotFoundError(f"No public key found for user '{username}'")

        with open(public_path, 'rb') as f:
            return f.read()

    def get_private_key(self, username: str) -> bytes:
        """Load a user's private key."""
        if username in self.metadata.get('revoked', []):
            raise ValueError(f"Key for user '{username}' has been revoked")

        private_path = os.path.join(self.keys_dir, username, 'private_key.pem')
        if not os.path.exists(private_path):
            raise FileNotFoundError(f"No private key found for user '{username}'")

        with open(private_path, 'rb') as f:
            return f.read()

    def rotate_keys(self, username: str, key_size: int = 2048) -> dict:
        """
        Rotate keys for a user (generates new keys, archives old).

        Args:
            username: The username to rotate keys for

        Returns:
            New key info dict
        """
        user_dir = os.path.join(self.keys_dir, username)

        # Archive old keys if they exist
        old_version = self.metadata['keys'].get(username, {}).get('version', 0)
        if old_version > 0:
            archive_dir = os.path.join(user_dir, f'archive_v{old_version}')
            os.makedirs(archive_dir, exist_ok=True)

            for key_file in ['private_key.pem', 'public_key.pem']:
                old_path = os.path.join(user_dir, key_file)
                if os.path.exists(old_path):
                    archive_path = os.path.join(archive_dir, key_file)
                    with open(old_path, 'rb') as f:
                        data = f.read()
                    with open(archive_path, 'wb') as f:
                        f.write(data)

        return self.generate_user_keys(username, key_size)

    def revoke_key(self, username: str) -> bool:
        """
        Revoke a user's keys.

        Returns:
            True if revoked successfully
        """
        if username not in self.metadata['keys']:
            return False

        if username not in self.metadata['revoked']:
            self.metadata['revoked'].append(username)

        self.metadata['keys'][username]['status'] = 'revoked'
        self.metadata['keys'][username]['revoked_at'] = datetime.utcnow().isoformat()
        self._save_metadata()
        return True

    def reinstate_key(self, username: str) -> bool:
        """Reinstate a previously revoked user's key."""
        if username in self.metadata['revoked']:
            self.metadata['revoked'].remove(username)
            self.metadata['keys'][username]['status'] = 'active'
            self._save_metadata()
            return True
        return False

    def is_key_valid(self, username: str) -> bool:
        """Check if a user's key is valid (exists and not revoked)."""
        if username in self.metadata.get('revoked', []):
            return False
        key_info = self.metadata['keys'].get(username)
        if not key_info:
            return False
        return key_info.get('status') == 'active'

    def get_key_info(self, username: str) -> dict:
        """Get metadata about a user's key."""
        return self.metadata['keys'].get(username, {})

    def list_all_keys(self) -> dict:
        """List all key metadata."""
        return self.metadata['keys']
