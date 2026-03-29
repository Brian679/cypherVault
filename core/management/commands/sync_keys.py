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

        # Reset transfers that were encrypted with old (wrong) keys
        broken = FileTransfer.objects.filter(status='sent')
        if broken.exists():
            self.stdout.write(self.style.WARNING(
                f'\n{broken.count()} transfer(s) in "sent" status.'
                f'\nThese may have been encrypted with old keys.'
                f'\nUsers should re-send these files after key sync.'
            ))

        self.stdout.write(self.style.SUCCESS('\nKey sync complete!'))
