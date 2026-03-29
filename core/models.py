"""
CipherVault Core Models
=======================
Database models for user profiles, file transfers, audit logs, and API keys.
"""

import uuid
import hashlib
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class UserProfile(models.Model):
    """Extended user profile with RSA key management."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    public_key = models.TextField(blank=True, help_text="RSA public key in PEM format")
    key_fingerprint = models.CharField(max_length=64, blank=True)
    key_version = models.PositiveIntegerField(default=0)
    key_created_at = models.DateTimeField(null=True, blank=True)
    api_key = models.CharField(max_length=64, blank=True, unique=True, null=True)
    is_key_revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} (v{self.key_version})"

    def generate_api_key(self):
        """Generate a unique API key."""
        raw = f"{self.user.username}{uuid.uuid4()}{timezone.now().isoformat()}"
        self.api_key = hashlib.sha256(raw.encode()).hexdigest()
        self.save()
        return self.api_key

    class Meta:
        ordering = ['-created_at']


class FileTransfer(models.Model):
    """Tracks individual file transfer operations."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('encrypting', 'Encrypting'),
        ('sent', 'Sent'),
        ('received', 'Received'),
        ('decrypting', 'Decrypting'),
        ('verified', 'Verified'),
        ('failed', 'Failed'),
        ('rejected', 'Rejected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_transfers')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_transfers')

    # File info
    original_filename = models.CharField(max_length=255)
    file_size = models.BigIntegerField(default=0)
    encrypted_file = models.FileField(upload_to='encrypted/', blank=True)
    decrypted_file = models.FileField(upload_to='decrypted/', blank=True)
    encrypted_aes_key = models.BinaryField(blank=True, null=True)

    # Security fields
    file_hash = models.CharField(max_length=64, help_text="SHA-256 hash of original file")
    received_hash = models.CharField(max_length=64, blank=True, help_text="SHA-256 hash computed after decryption")
    digital_signature = models.BinaryField(blank=True, null=True)
    signature_verified = models.BooleanField(default=False)
    hash_verified = models.BooleanField(default=False)

    # Status & timestamps
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Performance metrics
    encryption_time_ms = models.FloatField(default=0)
    hashing_time_ms = models.FloatField(default=0)
    signing_time_ms = models.FloatField(default=0)
    total_time_ms = models.FloatField(default=0)
    cpu_usage_percent = models.FloatField(default=0)
    memory_usage_mb = models.FloatField(default=0)

    def __str__(self):
        return f"{self.sender.username} -> {self.receiver.username}: {self.original_filename}"

    @property
    def is_integrity_verified(self):
        return self.hash_verified and self.signature_verified

    class Meta:
        ordering = ['-created_at']


class AuditLog(models.Model):
    """
    Tamper-evident audit log with hash chaining.
    Each entry's chain_hash = SHA256(previous_chain_hash + current_log_data)
    """

    ACTIONS = [
        ('auth_login', 'User Login'),
        ('auth_logout', 'User Logout'),
        ('auth_fail', 'Authentication Failed'),
        ('file_upload', 'File Uploaded'),
        ('file_encrypt', 'File Encrypted'),
        ('file_send', 'File Sent'),
        ('file_receive', 'File Received'),
        ('file_decrypt', 'File Decrypted'),
        ('hash_verify_pass', 'Hash Verification Passed'),
        ('hash_verify_fail', 'Hash Verification Failed'),
        ('sig_verify_pass', 'Signature Verification Passed'),
        ('sig_verify_fail', 'Signature Verification Failed'),
        ('key_generate', 'Key Generated'),
        ('key_rotate', 'Key Rotated'),
        ('key_revoke', 'Key Revoked'),
        ('transfer_complete', 'Transfer Complete'),
        ('transfer_reject', 'Transfer Rejected'),
        ('integrity_fail', 'Integrity Check Failed'),
        ('attack_detected', 'Potential Attack Detected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=30, choices=ACTIONS)
    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='targeted_logs')
    transfer = models.ForeignKey(FileTransfer, on_delete=models.SET_NULL, null=True, blank=True)

    # Log content
    file_hash = models.CharField(max_length=64, blank=True)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    verification_result = models.BooleanField(null=True, blank=True)

    # Tamper-evident chain
    chain_hash = models.CharField(max_length=64, help_text="Hash chain: SHA256(prev_hash + current_data)")
    previous_hash = models.CharField(max_length=64, blank=True, default='GENESIS')

    class Meta:
        ordering = ['timestamp']
        get_latest_by = 'timestamp'

    def __str__(self):
        actor_name = self.actor.username if self.actor else 'system'
        return f"[{self.timestamp}] {actor_name}: {self.get_action_display()}"

    def get_log_data(self) -> str:
        """Serialize log entry data for hash computation."""
        return (
            f"{self.timestamp.isoformat() if self.timestamp else ''}"
            f"|{self.action}"
            f"|{self.actor.username if self.actor else 'system'}"
            f"|{self.target_user.username if self.target_user else ''}"
            f"|{self.file_hash}"
            f"|{self.details}"
            f"|{self.verification_result}"
        )
