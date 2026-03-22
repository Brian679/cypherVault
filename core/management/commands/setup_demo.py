"""
Management command to set up demo users and keys for CipherVault.
Usage: python manage.py setup_demo
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

from core.models import UserProfile
from core.crypto import KeyManager


class Command(BaseCommand):
    help = 'Set up demo users with RSA keys for testing CipherVault'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete existing demo users and recreate them',
        )

    def handle(self, *args, **options):
        import os
        from django.conf import settings as django_settings
        keys_dir = os.path.join(django_settings.BASE_DIR, 'keys')
        key_manager = KeyManager(keys_dir)

        demo_users = [
            {
                'username': 'alice',
                'email': 'alice@ciphervault.local',
                'password': 'SecurePass123!',
                'first_name': 'Alice',
                'last_name': 'Investigator',
            },
            {
                'username': 'bob',
                'email': 'bob@ciphervault.local',
                'password': 'SecurePass123!',
                'first_name': 'Bob',
                'last_name': 'Analyst',
            },
            {
                'username': 'charlie',
                'email': 'charlie@ciphervault.local',
                'password': 'SecurePass123!',
                'first_name': 'Charlie',
                'last_name': 'Supervisor',
            },
        ]

        if options['reset']:
            for info in demo_users:
                User.objects.filter(username=info['username']).delete()
            self.stdout.write(self.style.WARNING('Deleted existing demo users.'))

        for info in demo_users:
            user, created = User.objects.get_or_create(
                username=info['username'],
                defaults={
                    'email': info['email'],
                    'first_name': info['first_name'],
                    'last_name': info['last_name'],
                }
            )

            if created:
                user.set_password(info['password'])
                user.save()

                # Generate RSA key pair and save to filesystem
                key_info = key_manager.generate_user_keys(info['username'])

                # Create user profile using the SAME keys
                profile, _ = UserProfile.objects.get_or_create(user=user)
                profile.public_key = key_info['public_key'].decode()
                profile.key_fingerprint = key_info['fingerprint']
                profile.save()

                self.stdout.write(
                    self.style.SUCCESS(
                        f'Created user: {info["username"]} '
                        f'(password: {info["password"]})'
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'User {info["username"]} already exists. '
                        f'Use --reset to recreate.'
                    )
                )

        # Create superuser if not exists
        if not User.objects.filter(is_superuser=True).exists():
            admin_user = User.objects.create_superuser(
                username='admin',
                email='admin@ciphervault.local',
                password='AdminPass123!',
                first_name='Admin',
                last_name='CipherVault',
            )
            key_info = key_manager.generate_user_keys('admin')

            profile, _ = UserProfile.objects.get_or_create(user=admin_user)
            profile.public_key = key_info['public_key'].decode()
            profile.key_fingerprint = key_info['fingerprint']
            profile.save()

            self.stdout.write(
                self.style.SUCCESS(
                    'Created superuser: admin (password: AdminPass123!)'
                )
            )

        self.stdout.write(self.style.SUCCESS('\nDemo setup complete!'))
        self.stdout.write('Available users:')
        for info in demo_users:
            self.stdout.write(
                f'  - {info["username"]} / {info["password"]}'
            )
        self.stdout.write('  - admin / AdminPass123!')
