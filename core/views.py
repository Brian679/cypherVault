"""
CipherVault Views
=================
Handles all web endpoints: authentication, file transfer,
dashboard, audit logs, and key management.
"""

import os
import base64
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils import timezone

from .models import UserProfile, FileTransfer, AuditLog
from .forms import LoginForm, RegisterForm, FileTransferForm
from .orchestrator import SecurityOrchestrator, PipelineError
from .logging_engine import LoggingEngine
from .performance import PerformanceMonitor
from .crypto import KeyManager


def get_client_ip(request):
    """Extract client IP from request."""
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


# ============================================================
# Authentication Views
# ============================================================

def login_view(request):
    """User login."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)

                # Ensure profile exists
                UserProfile.objects.get_or_create(user=user)

                LoggingEngine.log(
                    action='auth_login',
                    actor=user,
                    details=f"User '{username}' logged in",
                    ip_address=get_client_ip(request),
                )
                messages.success(request, f'Welcome back, {username}!')
                return redirect('dashboard')
            else:
                LoggingEngine.log(
                    action='auth_fail',
                    details=f"Failed login attempt for username '{username}'",
                    ip_address=get_client_ip(request),
                )
                messages.error(request, 'Invalid credentials.')
    else:
        form = LoginForm()

    return render(request, 'core/login.html', {'form': form})


def register_view(request):
    """User registration."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()

            # Create profile and generate keys
            profile = UserProfile.objects.create(user=user)
            km = KeyManager(os.path.join(settings.BASE_DIR, 'keys'))
            key_info = km.generate_user_keys(user.username)

            profile.public_key = key_info['public_key'].decode()
            profile.key_fingerprint = key_info['fingerprint']
            profile.key_version = 1
            profile.key_created_at = timezone.now()
            profile.save()

            LoggingEngine.log(
                action='key_generate',
                actor=user,
                details=f"RSA keys generated for user '{user.username}', "
                        f"fingerprint: {key_info['fingerprint']}",
                ip_address=get_client_ip(request),
            )

            login(request, user)
            messages.success(request, 'Account created! RSA keys have been generated.')
            return redirect('dashboard')
    else:
        form = RegisterForm()

    return render(request, 'core/register.html', {'form': form})


def logout_view(request):
    """User logout."""
    if request.user.is_authenticated:
        LoggingEngine.log(
            action='auth_logout',
            actor=request.user,
            details=f"User '{request.user.username}' logged out",
            ip_address=get_client_ip(request),
        )
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')


# ============================================================
# Dashboard
# ============================================================

@login_required
def dashboard_view(request):
    """Main dashboard showing transfer overview and system status."""
    user = request.user

    # Ensure profile
    profile, _ = UserProfile.objects.get_or_create(user=user)

    sent_transfers = FileTransfer.objects.filter(sender=user).order_by('-created_at')[:10]
    received_transfers = FileTransfer.objects.filter(receiver=user).order_by('-created_at')[:10]
    recent_logs = AuditLog.objects.filter(actor=user).order_by('-timestamp')[:10]

    # Stats
    total_sent = FileTransfer.objects.filter(sender=user).count()
    total_received = FileTransfer.objects.filter(receiver=user).count()
    verified_count = FileTransfer.objects.filter(
        receiver=user, status='verified'
    ).count()
    rejected_count = FileTransfer.objects.filter(
        receiver=user, status='rejected'
    ).count()

    # Pending incoming transfers
    pending_transfers = FileTransfer.objects.filter(
        receiver=user, status='sent'
    ).order_by('-created_at')

    context = {
        'profile': profile,
        'sent_transfers': sent_transfers,
        'received_transfers': received_transfers,
        'recent_logs': recent_logs,
        'total_sent': total_sent,
        'total_received': total_received,
        'verified_count': verified_count,
        'rejected_count': rejected_count,
        'pending_transfers': pending_transfers,
    }
    return render(request, 'core/dashboard.html', context)


# ============================================================
# File Transfer Views
# ============================================================

@login_required
def send_file_view(request):
    """Upload and send a file securely through the orchestrator pipeline."""
    if request.method == 'POST':
        form = FileTransferForm(request.POST, request.FILES, current_user=request.user)
        if form.is_valid():
            receiver = form.cleaned_data['receiver']
            uploaded_file = form.cleaned_data['file']
            file_data = uploaded_file.read()
            filename = uploaded_file.name

            try:
                orchestrator = SecurityOrchestrator()
                result = orchestrator.send_file(
                    sender=request.user,
                    receiver=receiver,
                    file_data=file_data,
                    filename=filename,
                    ip_address=get_client_ip(request),
                )
                messages.success(
                    request,
                    f"File '{filename}' sent securely to {receiver.username}. "
                    f"Transfer ID: {result['transfer_id']}"
                )
                return redirect('transfer_detail', transfer_id=result['transfer_id'])

            except PipelineError as e:
                messages.error(request, f"Transfer failed at '{e.step}': {e.message}")
            except Exception as e:
                messages.error(request, f"Unexpected error: {str(e)}")
    else:
        form = FileTransferForm(current_user=request.user)

    return render(request, 'core/send_file.html', {'form': form})


@login_required
def receive_file_view(request, transfer_id):
    """Receive and verify a file through the orchestrator pipeline."""
    transfer = get_object_or_404(FileTransfer, id=transfer_id)

    if transfer.receiver != request.user:
        messages.error(request, 'You are not the intended recipient of this transfer.')
        return redirect('dashboard')

    result = None
    if request.method == 'POST':
        try:
            orchestrator = SecurityOrchestrator()
            result = orchestrator.receive_file(
                receiver=request.user,
                transfer_id=str(transfer_id),
                ip_address=get_client_ip(request),
            )

            if result['success']:
                messages.success(request, 'File received and integrity verified!')
            else:
                reasons = ', '.join(result.get('rejection_reason', ['Unknown']))
                messages.error(request, f'File REJECTED: {reasons}')

        except PipelineError as e:
            messages.error(request, f"Receive failed at '{e.step}': {e.message}")
            result = {'success': False, 'error': str(e)}

    # Refresh transfer from DB
    transfer.refresh_from_db()

    return render(request, 'core/receive_file.html', {
        'transfer': transfer,
        'result': result,
    })


@login_required
def download_decrypted_view(request, transfer_id):
    """Download the decrypted file after successful verification."""
    transfer = get_object_or_404(FileTransfer, id=transfer_id)

    if transfer.receiver != request.user:
        messages.error(request, 'Access denied.')
        return redirect('dashboard')

    if transfer.status != 'verified':
        messages.error(request, 'File has not been verified yet.')
        return redirect('receive_file', transfer_id=transfer_id)

    # Re-decrypt the file for download
    try:
        orchestrator = SecurityOrchestrator()
        receiver_private_key = orchestrator.key_manager.get_private_key(request.user.username)

        from .crypto import RSACipher, AESCipher
        aes_key = RSACipher.decrypt_key(
            bytes(transfer.encrypted_aes_key), receiver_private_key
        )
        encrypted_data = transfer.encrypted_file.read()
        decrypted_data = AESCipher.decrypt(encrypted_data, aes_key)

        response = HttpResponse(decrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{transfer.original_filename}"'
        return response

    except Exception as e:
        messages.error(request, f'Download failed: {str(e)}')
        return redirect('receive_file', transfer_id=transfer_id)


@login_required
def transfer_detail_view(request, transfer_id):
    """View detailed information about a transfer."""
    transfer = get_object_or_404(FileTransfer, id=transfer_id)

    if transfer.sender != request.user and transfer.receiver != request.user:
        messages.error(request, 'Access denied.')
        return redirect('dashboard')

    logs = AuditLog.objects.filter(transfer=transfer).order_by('timestamp')

    return render(request, 'core/transfer_detail.html', {
        'transfer': transfer,
        'logs': logs,
    })


@login_required
def transfer_list_view(request):
    """List all transfers for the current user."""
    sent = FileTransfer.objects.filter(sender=request.user).order_by('-created_at')
    received = FileTransfer.objects.filter(receiver=request.user).order_by('-created_at')

    return render(request, 'core/transfer_list.html', {
        'sent_transfers': sent,
        'received_transfers': received,
    })


# ============================================================
# Key Management Views
# ============================================================

@login_required
def key_management_view(request):
    """View and manage RSA keys."""
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'rotate':
            try:
                km = KeyManager(os.path.join(settings.BASE_DIR, 'keys'))
                key_info = km.rotate_keys(request.user.username)

                profile.public_key = key_info['public_key'].decode()
                profile.key_fingerprint = key_info['fingerprint']
                profile.key_version += 1
                profile.key_created_at = timezone.now()
                profile.save()

                LoggingEngine.log(
                    action='key_rotate',
                    actor=request.user,
                    details=f"Keys rotated to v{profile.key_version}, "
                            f"fingerprint: {key_info['fingerprint']}",
                    ip_address=get_client_ip(request),
                )
                messages.success(request, f'Keys rotated to version {profile.key_version}.')

            except Exception as e:
                messages.error(request, f'Key rotation failed: {str(e)}')

        elif action == 'generate_api_key':
            api_key = profile.generate_api_key()
            messages.success(request, f'New API key generated: {api_key[:8]}...')

    return render(request, 'core/key_management.html', {
        'profile': profile,
    })


# ============================================================
# Audit & Monitoring Views
# ============================================================

@login_required
def audit_log_view(request):
    """View audit logs and chain verification."""
    if not request.user.is_staff:
        # Non-staff users see only their own logs
        logs = AuditLog.objects.filter(actor=request.user).order_by('-timestamp')[:100]
        chain_status = None
    else:
        logs = AuditLog.objects.order_by('-timestamp')[:200]
        chain_status = LoggingEngine.verify_chain()

    return render(request, 'core/audit_log.html', {
        'logs': logs,
        'chain_status': chain_status,
        'is_admin': request.user.is_staff,
    })


@login_required
def performance_dashboard_view(request):
    """Performance monitoring dashboard."""
    transfers = FileTransfer.objects.filter(
        sender=request.user
    ).exclude(total_time_ms=0).order_by('-created_at')[:50]

    # Aggregate stats
    if transfers:
        avg_encryption = sum(t.encryption_time_ms for t in transfers) / len(transfers)
        avg_hashing = sum(t.hashing_time_ms for t in transfers) / len(transfers)
        avg_signing = sum(t.signing_time_ms for t in transfers) / len(transfers)
        avg_total = sum(t.total_time_ms for t in transfers) / len(transfers)
    else:
        avg_encryption = avg_hashing = avg_signing = avg_total = 0

    system_stats = PerformanceMonitor.get_system_stats()

    return render(request, 'core/performance.html', {
        'transfers': transfers,
        'avg_encryption': round(avg_encryption, 2),
        'avg_hashing': round(avg_hashing, 2),
        'avg_signing': round(avg_signing, 2),
        'avg_total': round(avg_total, 2),
        'system_stats': system_stats,
    })


# ============================================================
# API Endpoints (for programmatic access)
# ============================================================

@csrf_exempt
def api_send_file(request):
    """API endpoint for sending files using API key authentication."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    api_key = request.META.get('HTTP_X_API_KEY', '')
    if not api_key:
        return JsonResponse({'error': 'API key required'}, status=401)

    try:
        profile = UserProfile.objects.get(api_key=api_key)
        sender = profile.user
    except UserProfile.DoesNotExist:
        LoggingEngine.log(
            action='auth_fail',
            details=f"Invalid API key used: {api_key[:8]}...",
            ip_address=get_client_ip(request),
        )
        return JsonResponse({'error': 'Invalid API key'}, status=401)

    receiver_username = request.POST.get('receiver')
    if not receiver_username:
        return JsonResponse({'error': 'Receiver username required'}, status=400)

    try:
        from django.contrib.auth.models import User
        receiver = User.objects.get(username=receiver_username)
    except User.DoesNotExist:
        return JsonResponse({'error': 'Receiver not found'}, status=404)

    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return JsonResponse({'error': 'File required'}, status=400)

    file_data = uploaded_file.read()
    filename = uploaded_file.name

    try:
        orchestrator = SecurityOrchestrator()
        result = orchestrator.send_file(
            sender=sender,
            receiver=receiver,
            file_data=file_data,
            filename=filename,
            ip_address=get_client_ip(request),
        )
        return JsonResponse(result, status=201)

    except PipelineError as e:
        return JsonResponse({
            'error': f"Pipeline failed at '{e.step}': {e.message}"
        }, status=400)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
def api_receive_file(request, transfer_id):
    """API endpoint for receiving files using API key authentication."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    api_key = request.META.get('HTTP_X_API_KEY', '')
    if not api_key:
        return JsonResponse({'error': 'API key required'}, status=401)

    try:
        profile = UserProfile.objects.get(api_key=api_key)
        receiver = profile.user
    except UserProfile.DoesNotExist:
        return JsonResponse({'error': 'Invalid API key'}, status=401)

    try:
        orchestrator = SecurityOrchestrator()
        result = orchestrator.receive_file(
            receiver=receiver,
            transfer_id=transfer_id,
            ip_address=get_client_ip(request),
        )
        return JsonResponse(result)

    except PipelineError as e:
        return JsonResponse({
            'error': f"Pipeline failed at '{e.step}': {e.message}"
        }, status=400)


@csrf_exempt
def api_verify_chain(request):
    """API endpoint to verify audit log chain integrity."""
    api_key = request.META.get('HTTP_X_API_KEY', '')
    if not api_key:
        return JsonResponse({'error': 'API key required'}, status=401)

    try:
        profile = UserProfile.objects.get(api_key=api_key)
        if not profile.user.is_staff:
            return JsonResponse({'error': 'Admin access required'}, status=403)
    except UserProfile.DoesNotExist:
        return JsonResponse({'error': 'Invalid API key'}, status=401)

    result = LoggingEngine.verify_chain()
    return JsonResponse(result)
