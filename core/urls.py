"""
CipherVault URL Configuration
==============================
URL patterns for the core application.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard
    path('', views.dashboard_view, name='dashboard'),

    # File Transfer
    path('send/', views.send_file_view, name='send_file'),
    path('receive/<uuid:transfer_id>/', views.receive_file_view, name='receive_file'),
    path('download/<uuid:transfer_id>/', views.download_decrypted_view, name='download_file'),
    path('transfer/<uuid:transfer_id>/', views.transfer_detail_view, name='transfer_detail'),
    path('transfers/', views.transfer_list_view, name='transfer_list'),

    # Key Management
    path('keys/', views.key_management_view, name='key_management'),

    # Audit & Monitoring
    path('audit/', views.audit_log_view, name='audit_log'),
    path('performance/', views.performance_dashboard_view, name='performance'),

    # API Endpoints
    path('api/send/', views.api_send_file, name='api_send'),
    path('api/receive/<str:transfer_id>/', views.api_receive_file, name='api_receive'),
    path('api/verify-chain/', views.api_verify_chain, name='api_verify_chain'),
]
