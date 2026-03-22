# Deploying CipherVault to PythonAnywhere

## Prerequisites
- A PythonAnywhere account (free tier works)
- Git repo pushed to: https://github.com/Brian679/cypherVault

---

## Step-by-Step Deployment

### 1. Open a Bash Console on PythonAnywhere

Go to **Consoles** → **Start a new console** → **Bash**

### 2. Clone the Repository

```bash
cd ~
git clone https://github.com/Brian679/cypherVault.git
```

### 3. Create a Virtual Environment

```bash
cd ~/cypherVault
mkvirtualenv --python=/usr/bin/python3.12 ciphervault-env
```

> If `python3.12` is not available, use `python3.10` instead — check available versions with `ls /usr/bin/python3.*`

### 4. Install Dependencies

```bash
workon ciphervault-env
pip install -r requirements.txt
```

### 5. Set Environment Variables

Generate a production secret key:
```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Then add it to your `.env` or set it in the WSGI file (Step 7).

### 6. Update `ALLOWED_HOSTS`

Edit `~/cypherVault/cipher_vault/settings.py`:

Replace `YOUR_PA_USERNAME` with your actual PythonAnywhere username in the `PYTHONANYWHERE_USERNAME` line, or set the environment variable.

```python
PYTHONANYWHERE_USERNAME = 'your_actual_username'
```

### 7. Configure the WSGI File

Go to **Web** tab → Click on your web app → Find the **WSGI configuration file** link (e.g., `/var/www/your_username_pythonanywhere_com_wsgi.py`)

Replace its contents with:

```python
import os
import sys

project_home = '/home/YOUR_USERNAME/cypherVault'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

os.environ['DJANGO_SETTINGS_MODULE'] = 'cipher_vault.settings'
os.environ['DJANGO_DEBUG'] = 'False'
os.environ['DJANGO_SECRET_KEY'] = 'YOUR-GENERATED-SECRET-KEY'
os.environ['PYTHONANYWHERE_USERNAME'] = 'YOUR_USERNAME'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Replace `YOUR_USERNAME` with your PythonAnywhere username and `YOUR-GENERATED-SECRET-KEY` with the key from Step 5.

### 8. Run Migrations & Collect Static Files

Back in the **Bash console**:

```bash
workon ciphervault-env
cd ~/cypherVault
python manage.py migrate
python manage.py collectstatic --noinput
```

### 9. Create Required Directories

```bash
mkdir -p ~/cypherVault/media/uploads
mkdir -p ~/cypherVault/media/encrypted
mkdir -p ~/cypherVault/logs
mkdir -p ~/cypherVault/keys
```

### 10. Set Up Demo Users (Optional)

```bash
python manage.py setup_demo
```

Or create just a superuser:
```bash
python manage.py createsuperuser
```

### 11. Configure Static & Media Files on PythonAnywhere

Go to **Web** tab → **Static files** section → Add these entries:

| URL | Directory |
|-----|-----------|
| `/static/` | `/home/YOUR_USERNAME/cypherVault/staticfiles` |
| `/media/` | `/home/YOUR_USERNAME/cypherVault/media` |

### 12. Set the Virtualenv Path

On the **Web** tab, under **Virtualenv**, enter:

```
/home/YOUR_USERNAME/.virtualenvs/ciphervault-env
```

### 13. Reload the Web App

Click the **Reload** button on the Web tab.

Your app should now be live at: `https://YOUR_USERNAME.pythonanywhere.com`

---

## Updating After Code Changes

```bash
cd ~/cypherVault
git pull origin main
workon ciphervault-env
pip install -r requirements.txt
python manage.py migrate
python manage.py collectstatic --noinput
```

Then click **Reload** on the Web tab.

---

## Troubleshooting

- **500 errors**: Check the error log on the Web tab
- **Static files not loading**: Verify the static files mapping in the Web tab
- **Module not found**: Make sure the virtualenv path is correct
- **CSRF errors**: Ensure `ALLOWED_HOSTS` includes your `.pythonanywhere.com` domain
