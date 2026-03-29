"""
Management command to sync RSA keys between disk and database.
Usage: python manage.py sync_keys
"""

import os
from django.core.management.base import BaseCommand
from django.conf import settings

from core.models import UserProfile, FileTransfer
from core.crypto import KeyManager


class Command(BaseCommand):
    help = 'Sync RSA keys: update DB public keys from disk keys and reset broken transfers'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clean',
            action='store_true',
            help='Delete all existing transfers (needed when keys were out of sync)',
        )

    def handle(self, *args, **options):
        keys_dir = os.path.join(settings.BASE_DIR, 'keys')
        km = KeyManager(keys_dir)

        synced = 0
        for profile in UserProfile.objects.all():
            username = profile.user.username
            try:
                disk_pub = km.get_public_key(username).decode()
            except FileNotFoundError:
                self.stdout.write(self.style.WARNING(
                    f'  No disk keys for {username} — generating new keys...'
                ))
                key_info = km.generate_user_keys(username)
                disk_pub = key_info['public_key'].decode()

            if profile.public_key != disk_pub:
                self.stdout.write(self.style.WARNING(
                    f'  {username}: DB key differs from disk — updating DB'
                ))
                profile.public_key = disk_pub
                profile.save()
                synced += 1
            else:
                self.stdout.write(f'  {username}: keys in sync ✓')

        self.stdout.write(self.style.SUCCESS(f'\nSynced {synced} user(s).'))

        # Clean up broken transfers if requested
        if options['clean']:
            count = FileTransfer.objects.all().count()
            FileTransfer.objects.all().delete()
            self.stdout.write(self.style.WARNING(
                f'\nDeleted {count} transfer(s). Users can now send fresh files.'
            ))
        else:
            broken = FileTransfer.objects.exclude(status__in=['verified', 'rejected']).count()
            if broken:
                self.stdout.write(self.style.WARNING(
                    f'\n{broken} transfer(s) may have been encrypted with old keys.'
                    f'\nRun with --clean to delete them: python manage.py sync_keys --clean'
                ))

        self.stdout.write(self.style.SUCCESS('\nKey sync complete!'))
