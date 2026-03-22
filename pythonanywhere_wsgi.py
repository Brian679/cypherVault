"""
PythonAnywhere WSGI Configuration
==================================
Copy this file's contents into your PythonAnywhere WSGI configuration file
located at: /var/www/cyphervault_pythonanywhere_com_wsgi.py
"""

import os
import sys

# Add your project directory to the sys.path
project_home = os.path.expanduser('~/cypherVault')
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables
os.environ['DJANGO_SETTINGS_MODULE'] = 'cipher_vault.settings'
os.environ['DJANGO_DEBUG'] = 'False'
os.environ['PYTHONANYWHERE_USERNAME'] = 'cyphervault'
# Generate a real secret key: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
# os.environ['DJANGO_SECRET_KEY'] = 'your-production-secret-key-here'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
