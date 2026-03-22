"""
CipherVault Admin Configuration
================================
"""

from django.contrib import admin
from .models import UserProfile, FileTransfer, AuditLog


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'key_fingerprint', 'key_version', 'is_key_revoked', 'created_at']
    list_filter = ['is_key_revoked', 'key_version']
    search_fields = ['user__username', 'key_fingerprint']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(FileTransfer)
class FileTransferAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'sender', 'receiver', 'original_filename',
        'status', 'hash_verified', 'signature_verified', 'created_at'
    ]
    list_filter = ['status', 'hash_verified', 'signature_verified']
    search_fields = ['sender__username', 'receiver__username', 'original_filename', 'file_hash']
    readonly_fields = ['id', 'created_at', 'completed_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'action', 'actor', 'target_user', 'verification_result', 'chain_hash']
    list_filter = ['action', 'verification_result']
    search_fields = ['actor__username', 'details', 'file_hash']
    readonly_fields = ['id', 'timestamp', 'chain_hash', 'previous_hash']
    ordering = ['-timestamp']
