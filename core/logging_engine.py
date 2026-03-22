"""
Tamper-Evident Logging Engine
=============================
Implements hash-chained audit logging where:
    Log_n = SHA256(Log_{n-1} + Current_Log_Data)

If any log entry is modified, the chain breaks, providing
forensic-grade tamper evidence.
"""

import hashlib
from django.utils import timezone
from django.contrib.auth.models import User


class LoggingEngine:
    """Tamper-evident logging with hash chain verification."""

    GENESIS_HASH = '0' * 64  # Genesis block hash

    @staticmethod
    def _compute_chain_hash(previous_hash: str, log_data: str) -> str:
        """Compute chain hash: SHA256(previous_hash + log_data)."""
        combined = f"{previous_hash}{log_data}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()

    @classmethod
    def log(cls, action: str, actor: User = None, target_user: User = None,
            transfer=None, file_hash: str = '', details: str = '',
            ip_address: str = None, verification_result: bool = None):
        """
        Create a new tamper-evident log entry.

        The chain_hash is computed as SHA256(previous_chain_hash + current_log_data).
        """
        from core.models import AuditLog

        # Get the previous log entry's chain hash
        try:
            last_log = AuditLog.objects.latest()
            previous_hash = last_log.chain_hash
        except AuditLog.DoesNotExist:
            previous_hash = cls.GENESIS_HASH

        # Create log entry (without saving yet to compute hash)
        log_entry = AuditLog(
            action=action,
            actor=actor,
            target_user=target_user,
            transfer=transfer,
            file_hash=file_hash,
            details=details,
            ip_address=ip_address,
            verification_result=verification_result,
            previous_hash=previous_hash,
            timestamp=timezone.now(),
        )

        # Compute chain hash
        log_data = log_entry.get_log_data()
        chain_hash = cls._compute_chain_hash(previous_hash, log_data)
        log_entry.chain_hash = chain_hash

        log_entry.save()
        return log_entry

    @classmethod
    def verify_chain(cls) -> dict:
        """
        Verify the entire audit log chain integrity.

        Returns:
            dict with:
                - valid: bool
                - total_entries: int
                - broken_at: index of first broken entry (or None)
                - details: str
        """
        from core.models import AuditLog

        logs = AuditLog.objects.order_by('timestamp')
        total = logs.count()

        if total == 0:
            return {
                'valid': True,
                'total_entries': 0,
                'broken_at': None,
                'details': 'No log entries to verify.',
            }

        previous_hash = cls.GENESIS_HASH

        for i, log_entry in enumerate(logs):
            # Verify the previous hash reference
            if log_entry.previous_hash != previous_hash:
                return {
                    'valid': False,
                    'total_entries': total,
                    'broken_at': i,
                    'details': f'Chain broken at entry {i}: previous_hash mismatch. '
                               f'Expected {previous_hash[:16]}..., '
                               f'got {log_entry.previous_hash[:16]}...',
                }

            # Recompute chain hash
            log_data = log_entry.get_log_data()
            expected_hash = cls._compute_chain_hash(previous_hash, log_data)

            if log_entry.chain_hash != expected_hash:
                return {
                    'valid': False,
                    'total_entries': total,
                    'broken_at': i,
                    'details': f'Chain broken at entry {i}: chain_hash mismatch. '
                               f'Expected {expected_hash[:16]}..., '
                               f'got {log_entry.chain_hash[:16]}...',
                }

            previous_hash = log_entry.chain_hash

        return {
            'valid': True,
            'total_entries': total,
            'broken_at': None,
            'details': f'All {total} log entries verified. Chain is intact.',
        }

    @classmethod
    def get_recent_logs(cls, count: int = 50):
        """Get the most recent audit log entries."""
        from core.models import AuditLog
        return AuditLog.objects.order_by('-timestamp')[:count]
