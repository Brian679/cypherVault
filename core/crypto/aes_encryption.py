"""
AES-256 Encryption Module
=========================
Handles symmetric encryption/decryption of files using AES-256-CBC.
"""

import os
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    """AES-256-CBC encryption/decryption engine."""

    KEY_SIZE = 32  # 256 bits
    BLOCK_SIZE = AES.block_size  # 16 bytes
    IV_SIZE = 16

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit AES key."""
        return os.urandom(AESCipher.KEY_SIZE)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """
        Encrypt data using AES-256-CBC.

        Returns: IV (16 bytes) + encrypted data
        """
        if len(key) != AESCipher.KEY_SIZE:
            raise ValueError(f"AES key must be {AESCipher.KEY_SIZE} bytes")

        iv = os.urandom(AESCipher.IV_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AESCipher.BLOCK_SIZE)
        encrypted = cipher.encrypt(padded_data)

        # Format: IV + encrypted_data
        return iv + encrypted

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypt AES-256-CBC encrypted data.

        Expects: IV (16 bytes) + encrypted data
        """
        if len(key) != AESCipher.KEY_SIZE:
            raise ValueError(f"AES key must be {AESCipher.KEY_SIZE} bytes")

        if len(encrypted_data) < AESCipher.IV_SIZE + AESCipher.BLOCK_SIZE:
            raise ValueError("Encrypted data too short")

        iv = encrypted_data[:AESCipher.IV_SIZE]
        ciphertext = encrypted_data[AESCipher.IV_SIZE:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AESCipher.BLOCK_SIZE)

        return decrypted

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
        """Encrypt a file and write to output path."""
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        encrypted = AESCipher.encrypt(plaintext, key)

        with open(output_path, 'wb') as f:
            # Write original file size first (8 bytes, big-endian)
            f.write(struct.pack('>Q', len(plaintext)))
            f.write(encrypted)

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
        """Decrypt a file and write to output path."""
        with open(input_path, 'rb') as f:
            original_size = struct.unpack('>Q', f.read(8))[0]
            encrypted = f.read()

        decrypted = AESCipher.decrypt(encrypted, key)

        # Trim to original size
        decrypted = decrypted[:original_size]

        with open(output_path, 'wb') as f:
            f.write(decrypted)
