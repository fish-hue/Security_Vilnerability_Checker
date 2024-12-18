# Security Vulnerability Checker

This script performs a set of security checks on your codebase to identify vulnerabilities such as outdated packages, hard-coded secrets, risky file permissions, SQL injections, XSS vulnerabilities, weak cryptographic algorithms, and insecure HTTP headers.

## Features
- **Outdated Python Packages**: Checks for outdated packages in your Python environment using `pip list --outdated`.
- **CVE Detection**: Queries the National Vulnerability Database (NVD) API to check for known CVEs related to outdated packages.
- **Hard-Coded Secrets**: Scans the specified directory for hard-coded sensitive information like API keys, passwords, and tokens.
- **Risky File Permissions**: Identifies files with risky or overly permissive file permissions (e.g., `777`, `775`).
- **SQL Injection**: Detects potential SQL injection vulnerabilities in source code files.
- **Cross-Site Scripting (XSS)**: Searches for potential XSS vulnerabilities in source code files.
- **Weak Cryptographic Algorithms**: Detects the use of weak cryptographic algorithms like MD5 and SHA1.
- **Insecure HTTP Headers**: Checks for the presence of important HTTP security headers (e.g., `Strict-Transport-Security`, `X-Content-Type-Options`, etc.) on a given URL.

## Prerequisites
- Python 3.x
- `pip` (for managing Python packages)
- Internet access (for querying CVE information)

## Installation

1. Clone the repository or download the script to your local machine.
2. Install required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    The script requires `requests` for HTTP requests, and `subprocess` for running commands.

## Usage

### Command-line Arguments
- `directory`: The directory to scan for vulnerabilities. (see included example_project)
- `--url` (optional): A URL to check for insecure HTTP headers. Default is `http://example.com`.

### Example Usage:
To run the security checks on a codebase:

```bash
python scvuln.py example_project http://example.com 

