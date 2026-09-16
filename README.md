# SORAN v2.0 - Advanced OSINT & Recon Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-red">
  <img src="https://img.shields.io/badge/Version-2.0-green">
  <img src="https://img.shields.io/badge/License-MIT-yellow">
</p>

SORAN is a powerful open-source intelligence and information gathering tool designed for Kali Linux.

## Features
- Fast and lightweight
- Built for Kali Linux & Termux
- Easy to use CLI
- Regular updates

##  How to Install & Run

### Method 1: Quick Start (Recommended for Kali)
```bash
# Clone the repo
git clone https://github.com/Tende123/soran.git

# Enter folder
cd soran

# Install requirements
pip3 install -r requirements.txt

# Give permission
chmod +x soran.py

# Run the tool
python3 soran.py

# Lookup a domain
soran.py -d google.com

# Short form
soran.py -d facebook.com

# If you installed as command
soran -d google.com
soran -d tiktok.com

# Help menu
python3 soran.py -h
python3 soran.py --help

# IP Lookup
python3 soran.py -i 8.8.8.8
soran -i 1.1.1.1

# Just run without flag (shows help)
python3 soran.py

 Features
-d / --domain : Domain lookup (google.com, facebook.com)
-i / --ip : IP lookup (8.8.8.8)
Fast IP to Location
ISP & Org detection

Requirements
Python 3.8+
requests

Author
Peter Tende (Tende123)
GitHub: https://github.com/Tende123/soran

⚠️ Disclaimer
For EDUCATIONAL purpose only.

License
MIT License
EOF
