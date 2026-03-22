"""
Digital Signature Module
========================
Provides digital signing and verification using RSA + SHA-256.
Ensures authenticity and non-repudiation of file transfers.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class SignatureEngine:
    """RSA digital signature engine for non-repudiation."""

    @staticmethod
    def sign(data: bytes, private_key_pem: bytes) -> bytes:
        """
        Sign data using RSA private key.

        Args:
            data: Raw data to sign (typically file hash bytes)
            private_key_pem: Sender's RSA private key in PEM format

        Returns:
            Digital signature bytes
        """
        rsa_key = RSA.import_key(private_key_pem)
        h = SHA256.new(data)
        signature = pkcs1_15.new(rsa_key).sign(h)
        return signature

    @staticmethod
    def sign_hash(file_hash: str, private_key_pem: bytes) -> bytes:
        """
        Sign a hex-encoded hash string.

        Args:
            file_hash: SHA-256 hash hex string of the file
            private_key_pem: Sender's RSA private key

        Returns:
            Digital signature bytes
        """
        return SignatureEngine.sign(file_hash.encode('utf-8'), private_key_pem)

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        """
        Verify a digital signature using RSA public key.

        Args:
            data: Original data that was signed
            signature: The digital signature to verify
            public_key_pem: Sender's RSA public key in PEM format

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            rsa_key = RSA.import_key(public_key_pem)
            h = SHA256.new(data)
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def verify_hash(file_hash: str, signature: bytes, public_key_pem: bytes) -> bool:
        """
        Verify a signature against a hex-encoded hash string.

        Args:
            file_hash: SHA-256 hash hex string
            signature: Digital signature bytes
            public_key_pem: Sender's RSA public key

        Returns:
            True if valid, False otherwise
        """
        return SignatureEngine.verify(
            file_hash.encode('utf-8'), signature, public_key_pem
        )
