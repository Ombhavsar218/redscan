# 🚀 RedScan AI - 5-Minute Quickstart

Get your cybersecurity scanner running in 5 minutes!

## Step 1: Install Dependencies (1 min)

```bash
pip install -r requirements.txt
```

## Step 2: Setup Database (1 min)

```bash
python manage.py makemigrations
python manage.py migrate
```

## Step 3: Create Admin User (1 min)

```bash
python manage.py createsuperuser
```

Enter your details when prompted:
- Username: admin
- Email: (optional)
- Password: (your choice)

## Step 4: Start Server (30 seconds)

```bash
python manage.py runserver
```

You should see:
```
Starting development server at http://127.0.0.1:8000/
```

## Step 5: Create Your First Target (1 min)

1. Open browser: http://127.0.0.1:8000/admin/
2. Login with your admin credentials
3. Click "Targets" → "Add Target"
4. Fill in:
   - Name: `Test Scan`
   - Target type: `Domain`
   - Target value: `scanme.nmap.org`
   - Description: `Official Nmap test server`
5. Click "Save"
6. Note the Target ID (usually 1)

## Step 6: Run Your First Scan (30 seconds)

Open a new terminal and run:

```bash
curl -X POST http://127.0.0.1:8000/scan/start/ -H "Content-Type: application/json" -d "{\"target_id\": 1, \"scan_type\": \"recon\"}"
```

Or use Python:
```python
import requests
response = requests.post('http://127.0.0.1:8000/scan/start/', 
    json={'target_id': 1, 'scan_type': 'recon'})
print(response.json())
```

## Step 7: View Results (30 seconds)

1. Go to: http://127.0.0.1:8000/
2. You'll see your scan in the dashboard
3. Click "View" to see detailed results
4. Explore:
   - Open ports discovered
   - Vulnerabilities found
   - Risk score
   - Scan logs

## 🎉 Success!

You now have a working vulnerability scanner!

## What Just Happened?

1. **Database Setup**: Created tables for targets, scans, ports, vulnerabilities
2. **Admin User**: Created account to manage the system
3. **Target Created**: Added scanme.nmap.org (safe to scan)
4. **Scan Executed**: 
   - Scanned ports 1-1024
   - Detected open ports
   - Identified services
   - Checked for vulnerabilities
   - Calculated risk score
5. **Results Displayed**: Web dashboard shows everything

## Next Steps

### Beginner
- Scan your local machine (127.0.0.1)
- Try different targets
- Explore the admin panel
- Read the scan logs

### Intermediate
- Read `LEARNING_GUIDE.md` for concepts
- Modify `scanner.py` to add checks
- Customize the dashboard colors
- Add more vulnerability rules

### Advanced
- Integrate Nmap
- Add CVE database
- Implement authentication
- Create PDF reports

## Common Issues

### "Port already in use"
Another process is using port 8000. Try:
```bash
python manage.py runserver 8080
```

### "No module named django"
Install requirements:
```bash
pip install Django
```

### "Scan stuck in 'running'"
Check the terminal running the server for errors. The scan runs in a background thread.

### "No ports found"
- Firewall may be blocking
- Target may be down
- Try scanme.nmap.org (always available)

## Test Without Web Interface

Want to test the scanner directly?

```bash
python test_scanner.py
```

This runs a standalone scan and shows results in the terminal.

## File Guide

- `README.md` - Project overview
- `LEARNING_GUIDE.md` - Educational content (START HERE!)
- `COMMANDS.md` - Command reference
- `ARCHITECTURE.md` - System design
- `rescanai/scanner.py` - Core scanning logic
- `rescanai/models.py` - Database structure
- `rescanai/views.py` - Web interface logic

## Safety Reminder

⚠️ **IMPORTANT**: Only scan systems you own or have permission to test!

Safe targets for practice:
- `scanme.nmap.org` - Official Nmap test server
- `127.0.0.1` - Your own machine
- Your own VMs or containers

## Get Help

1. Check `LEARNING_GUIDE.md` for concepts
2. Check `COMMANDS.md` for syntax
3. Read error messages carefully
4. Search the Django documentation
5. Ask in cybersecurity communities

## Your First Customization

Try adding a new vulnerability check!

Edit `rescanai/scanner.py`, find `check_common_vulnerabilities()`, and add:

```python
# Check for HTTP
if 80 in self.open_ports:
    self.vulnerabilities.append({
        'port': 80,
        'title': 'HTTP Service Detected',
        'description': 'Unencrypted web traffic',
        'severity': 'low',
        'remediation': 'Consider using HTTPS'
    })
```

Restart the server and run a new scan to see your check in action!

## Celebrate! 🎉

You've built a real cybersecurity tool! This is the foundation for:
- Penetration testing
- Security auditing
- Network monitoring
- Vulnerability management

Keep learning, keep building, and most importantly - stay legal and ethical!

---

**Ready to dive deeper?** Read `LEARNING_GUIDE.md` next!
