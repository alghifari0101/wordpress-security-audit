# wordpress-security-audit
🔍 Overview
The WordPress Security Audit Tool is a Python script that performs extensive security checks on WordPress installations, either via online URL or local filesystem. This tool helps administrators identify vulnerabilities before they can be exploited by attackers.
✨ Features
Online WordPress Site Analysis

WordPress version detection
Security headers examination (HSTS, CSP, X-Frame-Options, etc.)
WP-Admin protection verification
Exposed sensitive files detection
Open directory listing checks
User enumeration vulnerability testing

Local WordPress Installation Analysis

WordPress version verification
File and directory permissions audit
wp-config.php security analysis
Plugin security auditing
Theme security checks
Database configuration security review

📋 Requirements

Python 3.6 or higher
requests library: pip install requests
Access to the WordPress site or local installation files

🚀 Installation
bash# Clone the repository
git clone https://github.com/yourusername/wordpress-security-audit.git

# Navigate to the directory
cd wordpress-security-audit

# Install dependencies
pip install -r requirements.txt

# Make script executable (Linux/macOS)
chmod +x wordpress_security_audit.py
💻 Usage
Basic Usage
bash# Run with interactive prompts
python3 wordpress_security_audit.py

# Audit online WordPress site
python3 wordpress_security_audit.py https://example.com

# Audit local WordPress installation
python3 wordpress_security_audit.py /var/www/html/wordpress
Options
When running without parameters, the script will interactively prompt you to:

Choose between online or local WordPress auditing
Enter the URL or filesystem path to your WordPress installation

📊 Sample Output
The tool generates two types of output:

A detailed JSON report file (wp_security_audit_YYYYMMDD_HHMMSS.json)
A terminal summary of key findings and recommendations

Terminal output example:
========================================================================
 WordPress Security Audit Tool 
========================================================================
[+] Target URL: https://example.com/

[+] Starting WordPress Security Audit...
[+] Verifying WordPress site...
[+] Checking WordPress version (remote)...
[+] WordPress version detected: 5.9.3
...
[+] Audit complete. Report saved to: wp_security_audit_20250520_123456.json

========================================================================
 Key Findings and Recommendations 
========================================================================

[+] WordPress Version: 5.9.3

[!] Exposed Sensitive Files:
  - readme.html
  - wp-config-sample.php

[!] Open Directories:
  - wp-content/uploads/

[+] Security Recommendations:
  1. Block access to sensitive file: readme.html
  2. Block access to sensitive file: wp-config-sample.php
  3. Disable directory listing for: wp-content/uploads/
  4. Add X-Frame-Options header to prevent clickjacking
  ...
📁 Report Structure
The JSON report contains comprehensive information including:

Timestamp and target information
WordPress version details
Server information
File permissions
Security configuration status
Plugin and theme vulnerabilities
Open directories and exposed files
Security headers analysis
WP-Admin protection status
Database security assessment
User enumeration vulnerability status
Complete list of security recommendations

⚠️ Limitations

Non-intrusive testing only (no active exploitation attempts)
Doesn't scan plugin/theme code for malicious content
Requires filesystem access for local audits
Some checks may require administrative privileges

🛡️ Responsible Usage
This tool is intended for security professionals, web administrators, and WordPress site owners to evaluate their own systems. Only use this tool on systems you own or have explicit permission to test.
🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

📝 License
This project is licensed under the MIT License - see the LICENSE file for details.
📬 Contact
Project Link: https://github.com/alghifari0101/wordpress-security-audit
