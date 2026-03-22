"""
SHA-256 Hashing Module
======================
Provides integrity verification through SHA-256 hash generation and comparison.
"""

import hashlib


class HashEngine:
    """SHA-256 hashing engine for file integrity verification."""

    ALGORITHM = 'sha256'

    @staticmethod
    def hash_data(data: bytes) -> str:
        """
        Generate SHA-256 hash of raw data.

        Returns:
            Hex-encoded hash string
        """
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_file(file_path: str) -> str:
        """
        Generate SHA-256 hash of a file (streaming for large files).

        Returns:
            Hex-encoded hash string
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def verify(data: bytes, expected_hash: str) -> bool:
        """
        Verify data integrity by comparing hashes.

        Returns:
            True if hashes match, False otherwise
        """
        computed = HashEngine.hash_data(data)
        return computed == expected_hash

    @staticmethod
    def verify_file(file_path: str, expected_hash: str) -> bool:
        """
        Verify file integrity by comparing hashes.

        Returns:
            True if hashes match, False otherwise
        """
        computed = HashEngine.hash_file(file_path)
        return computed == expected_hash

    @staticmethod
    def chain_hash(previous_hash: str, current_data: str) -> str:
        """
        Create a chained hash for tamper-evident logging.

        Hash_n = SHA256(Hash_{n-1} + Current_Data)

        Args:
            previous_hash: Hash of the previous log entry
            current_data: Current log entry data as string

        Returns:
            Chained hash
        """
        combined = f"{previous_hash}{current_data}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()
