# 🚀 RedScan AI — Intelligent Recon & Vulnerability Scanner

> A Django-based red team reconnaissance and vulnerability scanning platform inspired by professional security tools like Nessus and Burp Suite.

---

## 🔥 Overview

**RedScan AI** is a web-based cybersecurity platform designed to automate network reconnaissance and vulnerability scanning. It provides an interactive dashboard that simulates real-world red team workflows and helps users analyze attack surfaces and security risks.

This project demonstrates practical skills in:

- Cybersecurity (red teaming & vulnerability analysis)
- Django web development
- Network scanning & automation
- Security reporting
- Dashboard design and visualization

⚠️ **This tool is for educational and authorized lab use only.**

---

## ✨ Features

### 🔍 Reconnaissance Engine

- Automated port scanning using Nmap
- Service detection and enumeration
- Target profiling

### ⚠️ Vulnerability Scanning

- Basic web vulnerability detection
- Risk scoring system
- Exploit suggestions

### 📊 Interactive Dashboard

- Real-time scan monitoring
- Risk visualization charts
- Scan history tracking

### 📄 Reporting System

- PDF report generation
- Export options (JSON/CSV)
- Vulnerability summaries

### 🎯 Red Team Enhancements

- Attack surface visualization
- Severity classification
- Scan analytics

---

## 🛠 Tech Stack

### Backend

- Python
- Django
- SQLite

### Security Tools

- Nmap
- Custom Python scanning engine

### Frontend

- HTML/CSS
- Bootstrap/Tailwind CSS
- JavaScript

---

## 📁 Project Structure

```
redscan/
├── redscan/        # Django project configuration
├── rescanai/       # Main application
├── Documentation/  # Project documentation
├── manage.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/Ombhavsar218/redscan-ai.git
cd redscan-ai
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**Linux/Mac**

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Nmap

Download from:

👉 https://nmap.org/download.html

Verify installation:

```bash
nmap --version
```

### 5. Run database migrations

```bash
python manage.py migrate
```

### 6. Start the development server

```bash
python manage.py runserver
```

Open your browser and go to:

👉 http://127.0.0.1:8000

---

## 🧪 Usage

1. Login to the dashboard
2. Create a new scan
3. Enter a target IP or domain
4. View scan results and risk analysis
5. Generate reports

⚠️ Only scan systems you own or have explicit permission to test.

---

## 🎯 Learning Objectives

This project helps you understand:

- Network reconnaissance workflows
- Vulnerability scanning fundamentals
- Secure web application architecture
- Cybersecurity dashboard development

---

## 📜 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

**Om Bhavsar**

Cybersecurity enthusiast & developer

GitHub: https://github.com/Ombhavsar218 
LinkedIn: (optional)

---

## ⚠️ Disclaimer

This tool is intended strictly for **educational and ethical security testing** in authorized environments. The author is not responsible for misuse.
