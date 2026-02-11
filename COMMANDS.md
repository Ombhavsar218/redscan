# 🔴 RedScan AI - Command Reference

Quick reference for common commands and operations.

## 🚀 Initial Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Create database tables
python manage.py makemigrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Run setup script (creates demo target)
python manage.py shell < setup.py

# Start development server
python manage.py runserver
```

## 🌐 Access Points

- **Dashboard**: http://127.0.0.1:8000/
- **Admin Panel**: http://127.0.0.1:8000/admin/
- **Scan API**: http://127.0.0.1:8000/scan/start/
- **Scan Detail**: http://127.0.0.1:8000/scan/{id}/

## 🔧 Django Management Commands

```bash
# Create new app
python manage.py startapp appname

# Make migrations after model changes
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Open Django shell
python manage.py shell

# Create superuser
python manage.py createsuperuser

# Collect static files (for production)
python manage.py collectstatic

# Run tests
python manage.py test
```

## 📡 API Usage

### Start a Scan (curl)
```bash
curl -X POST http://127.0.0.1:8000/scan/start/ \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "scan_type": "recon"}'
```

### Start a Scan (Python)
```python
import requests

response = requests.post(
    'http://127.0.0.1:8000/scan/start/',
    json={
        'target_id': 1,
        'scan_type': 'recon'
    }
)

print(response.json())
# Output: {'success': True, 'scan_id': 1, 'message': 'Scan started'}
```

### Start a Scan (JavaScript)
```javascript
fetch('http://127.0.0.1:8000/scan/start/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        target_id: 1,
        scan_type: 'recon'
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

## 🐍 Django Shell Commands

```bash
# Open shell
python manage.py shell
```

```python
# Import models
from rescanai.models import Target, Scan, Port, Vulnerability
from django.contrib.auth.models import User

# Create a target
user = User.objects.first()
target = Target.objects.create(
    name="Test Target",
    target_type="ip",
    target_value="192.168.1.1",
    created_by=user
)

# List all targets
Target.objects.all()

# Get specific target
target = Target.objects.get(id=1)

# List scans for a target
target.scans.all()

# Get scan with vulnerabilities
scan = Scan.objects.get(id=1)
scan.vulnerabilities.all()

# Count critical vulnerabilities
Vulnerability.objects.filter(severity='critical').count()

# Delete old scans
Scan.objects.filter(status='failed').delete()
```

## 🧪 Testing Commands

```bash
# Test the scanner independently
python test_scanner.py

# Run Django tests
python manage.py test rescanai

# Test specific test case
python manage.py test rescanai.tests.TestScanner
```

## 🔍 Debugging

```bash
# Check for errors
python manage.py check

# Show migrations
python manage.py showmigrations

# SQL for a migration
python manage.py sqlmigrate rescanai 0001

# Database shell
python manage.py dbshell

# Show URLs
python manage.py show_urls  # Requires django-extensions
```

## 📊 Database Operations

```bash
# Backup database (SQLite)
copy db.sqlite3 db_backup.sqlite3

# Reset database (WARNING: Deletes all data)
del db.sqlite3
python manage.py migrate

# Export data
python manage.py dumpdata rescanai > backup.json

# Import data
python manage.py loaddata backup.json
```

## 🛠️ Common Modifications

### Add a New Vulnerability Check

Edit `rescanai/scanner.py`:
```python
def check_common_vulnerabilities(self):
    # Add your check
    if 3306 in self.open_ports:  # MySQL
        self.vulnerabilities.append({
            'port': 3306,
            'title': 'MySQL Database Exposed',
            'description': 'Database port accessible from network',
            'severity': 'high',
            'remediation': 'Restrict MySQL to localhost only'
        })
```

### Add a New Model Field

1. Edit `rescanai/models.py`:
```python
class Scan(models.Model):
    # Add new field
    scan_duration = models.IntegerField(default=0)  # seconds
```

2. Create and apply migration:
```bash
python manage.py makemigrations
python manage.py migrate
```

### Customize Port Range

Edit `rescanai/views.py` in `execute_scan()`:
```python
# Change from range(1, 1025) to:
open_ports = scanner.scan_ports(range(1, 65536))  # All ports
# or
open_ports = scanner.scan_ports([21, 22, 80, 443, 3389])  # Specific ports
```

## 🎨 UI Customization

### Change Dashboard Colors

Edit `rescanai/templates/rescanai/base.html`:
```css
/* Find these in the <style> section */
background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);  /* Background */
color: #e74c3c;  /* Primary color (red) */
color: #3498db;  /* Secondary color (blue) */
```

### Add Custom CSS

Create `rescanai/static/rescanai/style.css` and link in base.html:
```html
<link rel="stylesheet" href="{% static 'rescanai/style.css' %}">
```

## 🔐 Security Hardening

```python
# In redscan/settings.py

# Production settings
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']

# Security headers
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Change secret key
SECRET_KEY = 'your-new-secret-key-here'
```

## 📦 Deployment

```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn redscan.wsgi:application --bind 0.0.0.0:8000

# Collect static files
python manage.py collectstatic --noinput

# Set environment variables
set DJANGO_SETTINGS_MODULE=redscan.settings
set SECRET_KEY=your-secret-key
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find process using port 8000
netstat -ano | findstr :8000

# Kill process (Windows)
taskkill /PID <process_id> /F
```

### Migration Issues
```bash
# Reset migrations (WARNING: Deletes data)
python manage.py migrate rescanai zero
del rescanai\migrations\0*.py
python manage.py makemigrations rescanai
python manage.py migrate
```

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## 📝 Useful Queries

```python
# In Django shell

# Recent scans
Scan.objects.order_by('-started_at')[:5]

# Failed scans
Scan.objects.filter(status='failed')

# Targets with most vulnerabilities
from django.db.models import Count
Target.objects.annotate(
    vuln_count=Count('scans__vulnerabilities')
).order_by('-vuln_count')

# Average scan duration
from django.db.models import Avg
Scan.objects.aggregate(Avg('completed_at'))

# Vulnerabilities by severity
Vulnerability.objects.values('severity').annotate(Count('id'))
```

## 🎯 Quick Wins

```bash
# 1. Scan localhost
# Create target with 127.0.0.1, then:
curl -X POST http://127.0.0.1:8000/scan/start/ \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "scan_type": "recon"}'

# 2. View results
# Open: http://127.0.0.1:8000/scan/1/

# 3. Test scanner directly
python test_scanner.py
```

---

Keep this file handy as your quick reference guide! 🚀
