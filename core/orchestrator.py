"""
Security Orchestrator Layer
============================
Central controller that enforces the entire secure transfer pipeline.
Ensures NO step is skipped and provides automatic validation,
failure handling, and attack detection.

Pipeline:
    Authenticate → Hash → Sign → Encrypt → Send → Decrypt → Verify → Log
"""

import os
import base64
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from django.core.files.base import ContentFile

from .crypto import AESCipher, RSACipher, HashEngine, SignatureEngine, KeyManager
from .logging_engine import LoggingEngine
from .performance import PerformanceMonitor


class PipelineError(Exception):
    """Raised when the security pipeline fails at any step."""

    def __init__(self, step: str, message: str):
        self.step = step
        self.message = message
        super().__init__(f"Pipeline failed at '{step}': {message}")


class SecurityOrchestrator:
    """
    Orchestrates the complete secure file transfer pipeline.

    Enforces that every step is executed in order:
    1. Authentication check
    2. File hash generation (SHA-256)
    3. Digital signature (RSA + SHA-256)
    4. File encryption (AES-256)
    5. AES key encryption (RSA)
    6. Package and store
    7. (Receiver side) Decrypt AES key
    8. Decrypt file
    9. Verify signature
    10. Recompute and compare hash
    11. Log result
    """

    def __init__(self):
        keys_dir = os.path.join(settings.BASE_DIR, 'keys')
        self.key_manager = KeyManager(keys_dir)
        self.monitor = PerformanceMonitor()

    def send_file(self, sender, receiver, file_data: bytes, filename: str,
                  ip_address: str = None) -> dict:
        """
        Execute the complete SEND pipeline.

        Args:
            sender: Django User object (authenticated)
            receiver: Django User object
            file_data: Raw file bytes
            filename: Original filename
            ip_address: Sender's IP address

        Returns:
            dict with transfer details and metrics
        """
        from .models import FileTransfer

        self.monitor = PerformanceMonitor()
        self.monitor.start_total_timer()
        self.monitor.metrics.file_size_bytes = len(file_data)

        transfer = None
        try:
            # ---- Step 1: Authentication check ----
            if not sender.is_authenticated:
                LoggingEngine.log(
                    action='auth_fail',
                    details=f"Unauthenticated send attempt for file: {filename}",
                    ip_address=ip_address,
                )
                raise PipelineError('authentication', 'Sender is not authenticated')

            if not receiver.is_active:
                raise PipelineError('authentication', 'Receiver account is not active')

            # Verify keys exist
            sender_profile = sender.profile
            receiver_profile = receiver.profile

            if not sender_profile.public_key or sender_profile.is_key_revoked:
                raise PipelineError('authentication', 'Sender keys are missing or revoked')

            if not receiver_profile.public_key or receiver_profile.is_key_revoked:
                raise PipelineError('authentication', 'Receiver keys are missing or revoked')

            # Get keys
            sender_private_key = self.key_manager.get_private_key(sender.username)
            receiver_public_key = receiver_profile.public_key.encode()

            # ---- Step 2: Generate file hash ----
            with self.monitor.measure('hashing'):
                file_hash = HashEngine.hash_data(file_data)

            LoggingEngine.log(
                action='file_upload',
                actor=sender,
                target_user=receiver,
                file_hash=file_hash,
                details=f"File '{filename}' uploaded, size={len(file_data)} bytes",
                ip_address=ip_address,
            )

            # ---- Step 3: Digital signature ----
            with self.monitor.measure('signing'):
                signature = SignatureEngine.sign_hash(file_hash, sender_private_key)

            # ---- Step 4: Encrypt file with AES-256 ----
            with self.monitor.measure('encryption'):
                aes_key = AESCipher.generate_key()
                encrypted_data = AESCipher.encrypt(file_data, aes_key)

            LoggingEngine.log(
                action='file_encrypt',
                actor=sender,
                target_user=receiver,
                file_hash=file_hash,
                details=f"File encrypted with AES-256, encrypted size={len(encrypted_data)} bytes",
                ip_address=ip_address,
            )

            # ---- Step 5: Encrypt AES key with receiver's RSA public key ----
            with self.monitor.measure('key_encryption'):
                encrypted_aes_key = RSACipher.encrypt_key(aes_key, receiver_public_key)

            # ---- Step 6: Package and store ----
            self.monitor.stop_total_timer()
            metrics = self.monitor.get_metrics()

            transfer = FileTransfer(
                sender=sender,
                receiver=receiver,
                original_filename=filename,
                file_size=len(file_data),
                file_hash=file_hash,
                digital_signature=signature,
                encrypted_aes_key=encrypted_aes_key,
                status='sent',
                encryption_time_ms=metrics.encryption_time_ms,
                hashing_time_ms=metrics.hashing_time_ms,
                signing_time_ms=metrics.signing_time_ms,
                total_time_ms=metrics.total_time_ms,
                cpu_usage_percent=metrics.cpu_usage_percent,
                memory_usage_mb=metrics.memory_usage_mb,
            )

            # Save encrypted file
            encrypted_filename = f"{transfer.id}_{filename}.enc"
            transfer.encrypted_file.save(
                encrypted_filename,
                ContentFile(encrypted_data),
                save=False,
            )
            transfer.status = 'sent'
            transfer.save()

            LoggingEngine.log(
                action='file_send',
                actor=sender,
                target_user=receiver,
                transfer=transfer,
                file_hash=file_hash,
                details=f"Transfer {transfer.id} created successfully",
                ip_address=ip_address,
                verification_result=True,
            )

            return {
                'success': True,
                'transfer_id': str(transfer.id),
                'file_hash': file_hash,
                'filename': filename,
                'file_size': len(file_data),
                'encrypted_size': len(encrypted_data),
                'metrics': metrics.to_dict(),
            }

        except PipelineError as e:
            LoggingEngine.log(
                action='transfer_reject',
                actor=sender,
                details=f"Send pipeline failed at '{e.step}': {e.message}",
                ip_address=ip_address,
                verification_result=False,
            )
            if transfer and transfer.pk:
                transfer.status = 'failed'
                transfer.save()
            raise

        except Exception as e:
            LoggingEngine.log(
                action='transfer_reject',
                actor=sender if sender.is_authenticated else None,
                details=f"Unexpected error in send pipeline: {str(e)}",
                ip_address=ip_address,
                verification_result=False,
            )
            if transfer and transfer.pk:
                transfer.status = 'failed'
                transfer.save()
            raise PipelineError('unknown', str(e))

    def receive_file(self, receiver, transfer_id: str, ip_address: str = None) -> dict:
        """
        Execute the complete RECEIVE pipeline.

        Args:
            receiver: Django User object (authenticated)
            transfer_id: UUID of the transfer
            ip_address: Receiver's IP address

        Returns:
            dict with decrypted file data and verification results
        """
        from .models import FileTransfer

        self.monitor = PerformanceMonitor()
        self.monitor.start_total_timer()

        try:
            # ---- Step 1: Authentication check ----
            if not receiver.is_authenticated:
                LoggingEngine.log(
                    action='auth_fail',
                    details=f"Unauthenticated receive attempt for transfer: {transfer_id}",
                    ip_address=ip_address,
                )
                raise PipelineError('authentication', 'Receiver is not authenticated')

            transfer = FileTransfer.objects.get(id=transfer_id)

            if transfer.receiver != receiver:
                LoggingEngine.log(
                    action='attack_detected',
                    actor=receiver,
                    transfer=transfer,
                    details=f"User {receiver.username} attempted to access transfer "
                            f"meant for {transfer.receiver.username}",
                    ip_address=ip_address,
                    verification_result=False,
                )
                raise PipelineError('authentication', 'You are not the intended receiver')

            transfer.status = 'received'
            transfer.save()

            LoggingEngine.log(
                action='file_receive',
                actor=receiver,
                target_user=transfer.sender,
                transfer=transfer,
                file_hash=transfer.file_hash,
                details=f"Transfer {transfer_id} received by {receiver.username}",
                ip_address=ip_address,
            )

            # Get keys
            receiver_private_key = self.key_manager.get_private_key(receiver.username)
            sender_public_key = transfer.sender.profile.public_key.encode()

            # ---- Step 7: Decrypt AES key ----
            with self.monitor.measure('key_decryption'):
                aes_key = RSACipher.decrypt_key(
                    bytes(transfer.encrypted_aes_key),
                    receiver_private_key
                )

            # ---- Step 8: Decrypt file ----
            transfer.status = 'decrypting'
            transfer.save()

            with self.monitor.measure('decryption'):
                encrypted_data = transfer.encrypted_file.read()
                decrypted_data = AESCipher.decrypt(encrypted_data, aes_key)

            LoggingEngine.log(
                action='file_decrypt',
                actor=receiver,
                transfer=transfer,
                file_hash=transfer.file_hash,
                details=f"File decrypted, size={len(decrypted_data)} bytes",
                ip_address=ip_address,
            )

            # ---- Step 9: Verify digital signature ----
            with self.monitor.measure('verification'):
                signature_valid = SignatureEngine.verify_hash(
                    transfer.file_hash,
                    bytes(transfer.digital_signature),
                    sender_public_key,
                )

            transfer.signature_verified = signature_valid

            if signature_valid:
                LoggingEngine.log(
                    action='sig_verify_pass',
                    actor=receiver,
                    target_user=transfer.sender,
                    transfer=transfer,
                    file_hash=transfer.file_hash,
                    details="Digital signature verification PASSED",
                    ip_address=ip_address,
                    verification_result=True,
                )
            else:
                LoggingEngine.log(
                    action='sig_verify_fail',
                    actor=receiver,
                    target_user=transfer.sender,
                    transfer=transfer,
                    file_hash=transfer.file_hash,
                    details="Digital signature verification FAILED - possible tampering or spoofing!",
                    ip_address=ip_address,
                    verification_result=False,
                )

            # ---- Step 10: Recompute hash and compare ----
            with self.monitor.measure('hashing'):
                received_hash = HashEngine.hash_data(decrypted_data)

            transfer.received_hash = received_hash
            hash_valid = (received_hash == transfer.file_hash)
            transfer.hash_verified = hash_valid

            if hash_valid:
                LoggingEngine.log(
                    action='hash_verify_pass',
                    actor=receiver,
                    transfer=transfer,
                    file_hash=transfer.file_hash,
                    details=f"Hash verification PASSED. Hash: {received_hash[:16]}...",
                    ip_address=ip_address,
                    verification_result=True,
                )
            else:
                LoggingEngine.log(
                    action='hash_verify_fail',
                    actor=receiver,
                    transfer=transfer,
                    file_hash=transfer.file_hash,
                    details=f"Hash verification FAILED! "
                            f"Expected: {transfer.file_hash[:16]}..., "
                            f"Got: {received_hash[:16]}...",
                    ip_address=ip_address,
                    verification_result=False,
                )

            # ---- Step 11: Final verdict and log ----
            self.monitor.stop_total_timer()
            metrics = self.monitor.get_metrics()

            integrity_ok = signature_valid and hash_valid

            if integrity_ok:
                transfer.status = 'verified'
                transfer.completed_at = timezone.now()
            else:
                transfer.status = 'rejected'

            transfer.save()

            action = 'transfer_complete' if integrity_ok else 'integrity_fail'
            LoggingEngine.log(
                action=action,
                actor=receiver,
                target_user=transfer.sender,
                transfer=transfer,
                file_hash=transfer.file_hash,
                details=(
                    f"Transfer {'VERIFIED' if integrity_ok else 'REJECTED'}. "
                    f"Signature: {'PASS' if signature_valid else 'FAIL'}, "
                    f"Hash: {'PASS' if hash_valid else 'FAIL'}"
                ),
                ip_address=ip_address,
                verification_result=integrity_ok,
            )

            result = {
                'success': integrity_ok,
                'transfer_id': str(transfer_id),
                'filename': transfer.original_filename,
                'file_size': transfer.file_size,
                'signature_verified': signature_valid,
                'hash_verified': hash_valid,
                'original_hash': transfer.file_hash,
                'received_hash': received_hash,
                'metrics': metrics.to_dict(),
            }

            if integrity_ok:
                result['file_data'] = base64.b64encode(decrypted_data).decode()
            else:
                result['file_data'] = None
                result['rejection_reason'] = []
                if not signature_valid:
                    result['rejection_reason'].append('Signature verification failed')
                if not hash_valid:
                    result['rejection_reason'].append('Hash verification failed - file may have been tampered with')

            return result

        except PipelineError:
            raise
        except FileTransfer.DoesNotExist:
            LoggingEngine.log(
                action='transfer_reject',
                actor=receiver,
                details=f"Transfer {transfer_id} not found",
                ip_address=ip_address,
                verification_result=False,
            )
            raise PipelineError('lookup', f'Transfer {transfer_id} not found')
        except Exception as e:
            LoggingEngine.log(
                action='integrity_fail',
                actor=receiver,
                details=f"Unexpected error in receive pipeline: {str(e)}",
                ip_address=ip_address,
                verification_result=False,
            )
            raise PipelineError('unknown', str(e))
