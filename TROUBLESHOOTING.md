# 🔧 RedScan AI - Troubleshooting Guide

Common issues and their solutions.

---

## 🚨 Installation Issues

### "pip: command not found"
**Problem**: Python/pip not installed or not in PATH

**Solution**:
```bash
# Windows
python -m pip install -r requirements.txt

# Or download Python from python.org
```

### "No module named django"
**Problem**: Django not installed

**Solution**:
```bash
pip install Django
# or
pip install -r requirements.txt
```

### "Permission denied"
**Problem**: Need admin rights

**Solution**:
```bash
# Windows: Run as Administrator
# Or use --user flag
pip install --user -r requirements.txt
```

---

## 🗄️ Database Issues

### "no such table: rescanai_target"
**Problem**: Database not initialized

**Solution**:
```bash
python manage.py makemigrations
python manage.py migrate
```

### "UNIQUE constraint failed"
**Problem**: Trying to create duplicate entry

**Solution**:
- Check if target already exists
- Use different name/value
- Or delete existing entry in admin panel

### "Database is locked"
**Problem**: SQLite file locked by another process

**Solution**:
```bash
# Close all connections
# Restart Django server
# Or delete db.sqlite3 and recreate:
del db.sqlite3
python manage.py migrate
```

---

## 🌐 Server Issues

### "Port 8000 already in use"
**Problem**: Another process using port 8000

**Solution**:
```bash
# Option 1: Use different port
python manage.py runserver 8080

# Option 2: Find and kill process (Windows)
netstat -ano | findstr :8000
taskkill /PID <process_id> /F
```

### "Server not accessible from other machines"
**Problem**: Server only listening on localhost

**Solution**:
```bash
# Listen on all interfaces
python manage.py runserver 0.0.0.0:8000

# Update ALLOWED_HOSTS in settings.py
ALLOWED_HOSTS = ['*']  # For development only!
```

### "DisallowedHost error"
**Problem**: Host not in ALLOWED_HOSTS

**Solution**:
Edit `redscan/settings.py`:
```python
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'your-domain.com']
```

---

## 🔍 Scanning Issues

### "Scan stuck in 'running' status"
**Problem**: Scan thread crashed or hung

**Diagnosis**:
1. Check terminal for error messages
2. Look at scan logs in admin panel
3. Check if target is reachable

**Solution**:
```python
# In Django shell
from rescanai.models import Scan
scan = Scan.objects.get(id=1)
scan.status = 'failed'
scan.save()
```

### "No ports found"
**Problem**: Target unreachable or firewall blocking

**Diagnosis**:
```bash
# Test connectivity
ping scanme.nmap.org

# Test specific port
telnet scanme.nmap.org 80
```

**Solution**:
- Use known-good target: scanme.nmap.org
- Check firewall settings
- Try scanning localhost (127.0.0.1)
- Increase timeout in scanner.py

### "Connection refused"
**Problem**: Port closed or service not running

**This is normal!** Closed ports will show as not open.

### "Scan takes too long"
**Problem**: Scanning too many ports or slow network

**Solution**:
Edit `rescanai/views.py`, change port range:
```python
# Scan fewer ports
open_ports = scanner.scan_ports(range(1, 101))  # Only 1-100

# Or specific ports
open_ports = scanner.scan_ports([21, 22, 80, 443])
```

---

## 🔐 Permission Issues

### "Permission denied" when scanning
**Problem**: Some ports require admin/root

**Solution**:
- Ports 1-1024 may need elevated privileges
- Run as administrator (Windows)
- Or scan ports > 1024 only

### "Access denied" to admin panel
**Problem**: Not logged in or wrong credentials

**Solution**:
```bash
# Create new superuser
python manage.py createsuperuser

# Reset password
python manage.py changepassword username
```

---

## 🎨 UI Issues

### "Page not found (404)"
**Problem**: URL not configured

**Solution**:
- Check URL spelling
- Verify urls.py configuration
- Restart server after URL changes

### "Template not found"
**Problem**: Template file missing or wrong path

**Solution**:
- Check file exists: `rescanai/templates/rescanai/dashboard.html`
- Verify INSTALLED_APPS includes 'rescanai'
- Check template name in view

### "Static files not loading"
**Problem**: CSS/JS not found

**Solution**:
```bash
# Collect static files
python manage.py collectstatic

# Or use DEBUG=True in development
```

---

## 🐍 Python Errors

### "IndentationError"
**Problem**: Mixed tabs/spaces or wrong indentation

**Solution**:
- Use consistent indentation (4 spaces)
- Check the line mentioned in error
- Use a proper code editor

### "ImportError: No module named X"
**Problem**: Missing dependency

**Solution**:
```bash
pip install <module-name>
# or
pip install -r requirements.txt
```

### "SyntaxError"
**Problem**: Code syntax error

**Solution**:
- Check the line mentioned in error
- Look for missing colons, brackets, quotes
- Verify Python version (need 3.8+)

---

## 🔌 Network Errors

### "socket.timeout"
**Problem**: Connection timeout

**Solution**:
- Increase timeout in scanner.py
- Check network connectivity
- Verify target is online

### "socket.gaierror: Name or service not known"
**Problem**: DNS resolution failed

**Solution**:
- Check domain spelling
- Verify DNS is working
- Try IP address instead of domain

### "ConnectionRefusedError"
**Problem**: Port closed or service down

**This is expected** for closed ports. Not an error.

---

## 📊 Data Issues

### "No scans showing in dashboard"
**Problem**: No scans created yet

**Solution**:
1. Create target in admin panel
2. Start a scan via API
3. Refresh dashboard

### "Vulnerabilities not showing"
**Problem**: No vulnerabilities found or scan incomplete

**Solution**:
- Wait for scan to complete
- Check scan status
- Verify vulnerability detection logic

### "Risk score is 0"
**Problem**: No vulnerabilities found

**This is good!** Target is secure or no dangerous ports open.

---

## 🔄 Migration Issues

### "Migration conflicts"
**Problem**: Multiple migration files for same change

**Solution**:
```bash
# Delete migration files (except __init__.py)
del rescanai\migrations\0*.py

# Recreate
python manage.py makemigrations
python manage.py migrate
```

### "Table already exists"
**Problem**: Database out of sync with migrations

**Solution**:
```bash
# Option 1: Fake the migration
python manage.py migrate --fake

# Option 2: Reset database (DELETES DATA!)
del db.sqlite3
python manage.py migrate
```

---

## 🚀 Performance Issues

### "Scan is slow"
**Problem**: Too many ports or low concurrency

**Solution**:
Edit `rescanai/scanner.py`:
```python
# Increase workers (use cautiously)
scanner.scan_ports(range(1, 1025), max_workers=200)

# Reduce timeout
def scan_port(self, port: int, timeout: float = 0.5):
```

### "Server is slow"
**Problem**: Too many concurrent scans

**Solution**:
- Limit concurrent scans
- Use Celery for background tasks (Phase 2)
- Upgrade to PostgreSQL

### "Database growing too large"
**Problem**: Too many old scans

**Solution**:
```python
# In Django shell
from rescanai.models import Scan
from datetime import datetime, timedelta

# Delete scans older than 30 days
old_date = datetime.now() - timedelta(days=30)
Scan.objects.filter(created_at__lt=old_date).delete()
```

---

## 🔒 Security Issues

### "CSRF verification failed"
**Problem**: CSRF token missing or invalid

**Solution**:
- Use @csrf_exempt decorator (development only)
- Include CSRF token in forms
- For API, use token authentication

### "Secret key exposed"
**Problem**: SECRET_KEY in version control

**Solution**:
```python
# In settings.py
import os
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-only')

# Set environment variable
set SECRET_KEY=your-secret-key-here
```

---

## 🧪 Testing Issues

### "Test database creation failed"
**Problem**: Permission or path issue

**Solution**:
```bash
# Run tests with verbose output
python manage.py test --verbosity=2

# Or skip database tests
python manage.py test --keepdb
```

### "Import errors in tests"
**Problem**: Module path incorrect

**Solution**:
```python
# Use absolute imports
from rescanai.models import Target
# Not: from models import Target
```

---

## 💻 Windows-Specific Issues

### "python: command not found"
**Problem**: Python not in PATH

**Solution**:
```bash
# Use full path
C:\Python39\python.exe manage.py runserver

# Or use py launcher
py manage.py runserver
```

### "Scripts disabled"
**Problem**: PowerShell execution policy

**Solution**:
```powershell
# Run as Administrator
Set-ExecutionPolicy RemoteSigned

# Or use cmd instead of PowerShell
```

---

## 🐛 Debug Mode

### Enable detailed error messages

Edit `redscan/settings.py`:
```python
DEBUG = True

# Add this for more details
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
}
```

### Check scan logs

```python
# In Django shell
from rescanai.models import Scan, ScanLog

scan = Scan.objects.get(id=1)
for log in scan.logs.all():
    print(f"[{log.level}] {log.message}")
```

---

## 🆘 Still Stuck?

### Gather Information
1. Error message (full text)
2. What you were trying to do
3. What you expected to happen
4. What actually happened
5. Python version: `python --version`
6. Django version: `python -m django --version`

### Check These First
- [ ] Is the server running?
- [ ] Did you run migrations?
- [ ] Is the target reachable?
- [ ] Are there errors in the terminal?
- [ ] Did you check the scan logs?

### Get Help
1. Read error message carefully
2. Search error on Google
3. Check Django documentation
4. Ask in Django forums
5. Check GitHub issues

---

## 📚 Useful Commands for Debugging

```bash
# Check Django version
python -m django --version

# Validate project
python manage.py check

# Show all URLs
python manage.py show_urls

# Database shell
python manage.py dbshell

# Python shell with Django
python manage.py shell

# Run with verbose output
python manage.py runserver --verbosity=3

# Check for errors
python manage.py check --deploy
```

---

## 🎯 Prevention Tips

1. **Always activate virtual environment**
2. **Run migrations after model changes**
3. **Check terminal for errors**
4. **Test on safe targets first**
5. **Keep backups of database**
6. **Read error messages completely**
7. **Use version control (git)**
8. **Document your changes**

---

Remember: Every error is a learning opportunity! 🚀
