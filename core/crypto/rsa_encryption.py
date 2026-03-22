"""
RSA Encryption Module
=====================
Handles asymmetric encryption of AES keys using RSA-2048.
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


class RSACipher:
    """RSA-2048 encryption engine for key encapsulation."""

    KEY_SIZE = 2048

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> tuple:
        """
        Generate an RSA key pair.

        Returns:
            tuple: (private_key_pem: bytes, public_key_pem: bytes)
        """
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def save_keypair(private_path: str, public_path: str, key_size: int = 2048) -> tuple:
        """Generate and save an RSA key pair to files."""
        private_key, public_key = RSACipher.generate_keypair(key_size)

        os.makedirs(os.path.dirname(private_path), exist_ok=True)
        os.makedirs(os.path.dirname(public_path), exist_ok=True)

        with open(private_path, 'wb') as f:
            f.write(private_key)
        with open(public_path, 'wb') as f:
            f.write(public_key)

        return private_key, public_key

    @staticmethod
    def load_public_key(key_data: bytes) -> RSA.RsaKey:
        """Load an RSA public key from PEM data."""
        return RSA.import_key(key_data)

    @staticmethod
    def load_private_key(key_data: bytes) -> RSA.RsaKey:
        """Load an RSA private key from PEM data."""
        return RSA.import_key(key_data)

    @staticmethod
    def encrypt_key(aes_key: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt an AES key with an RSA public key.

        Args:
            aes_key: The AES-256 key to encrypt
            public_key_pem: RSA public key in PEM format

        Returns:
            Encrypted AES key
        """
        rsa_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.encrypt(aes_key)

    @staticmethod
    def decrypt_key(encrypted_key: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypt an AES key with an RSA private key.

        Args:
            encrypted_key: The encrypted AES key
            private_key_pem: RSA private key in PEM format

        Returns:
            Decrypted AES key
        """
        rsa_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.decrypt(encrypted_key)
