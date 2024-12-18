import subprocess
import json
import os
import re
import requests
from pathlib import Path
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize global variable to store results
findings = {
    "outdated_packages": [],
    "cve_findings": [],
    "secrets_found": [],
    "risky_permissions": [],
    "sql_injections": [],
    "xss_vulnerabilities": [],
    "insecure_http_headers": [],
    "weak_cryptographic_algorithms": []
}

# Define regex patterns as constants (removed `(?i)` for simplicity)
SECRET_PATTERNS_HARDCODED = [
    r"(api_key|password|secret|token|aws_access_key_id|aws_secret_access_key|client_id|client_secret|private_key|auth_token|db_password|username|login|access_token|access_key)",
    r"(key=|passwd=|apikey=|authorization=|credentials=|secret_key=|bearer_token=|secret_token=|app_id=|rds_password|mongo_password|azure_secret|gcp_api_key|firebase_token|jwt_secret)"
]

SQL_PATTERNS = [
    r"(select.*from.*where|insert.*into.*values|drop.*table|union.*select.*from)",
    r"(--\s*|#.*|select.*sleep|select.*benchmark)",
    r"('|\");*--|or\s+1=1"
]

XSS_PATTERNS = [
    r"(<script.*>.*</script.*>)",
    r"(<img.*src=.*onerror=.*>)",
    r"(<iframe.*src=.*javascript:.*>)",
    r"(<.*?document\.cookie.*?>)"
]

WEAK_CRYPTO_PATTERNS = [
    r"(md5|sha1)"
]

HTTP_HEADERS = [
    'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 
    'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy'
]

# Function to validate if the directory exists
def validate_directory(directory: str) -> None:
    """Validate if the specified directory exists."""
    if not os.path.isdir(directory):
        logging.error(f"The directory '{directory}' does not exist or is not a valid directory.")
        exit(1)

# Function to run regex checks on files
def check_files_with_regex(directory: str, patterns: list, allowed_extensions: set, findings_key: str) -> None:
    """Check for patterns in files with specified extensions in the given directory."""
    logging.info(f"Checking for patterns in '{directory}'...")
    
    regex = re.compile('|'.join(patterns), re.IGNORECASE)  # Compile with case-insensitive flag
    matched_files = []

    for filepath in Path(directory).rglob('*'):
        if filepath.is_file() and filepath.suffix in allowed_extensions:
            with filepath.open('r', errors='ignore') as file:
                for line in file:
                    if regex.search(line):
                        matched_files.append(str(filepath))
                        break  # Stop after the first match

    if matched_files:
        for file in matched_files:
            findings[findings_key].append(f"Pattern found in: {file}")
    else:
        findings[findings_key].append("No patterns detected.")

# Function to check outdated Python packages
def check_outdated_packages() -> None:
    """Check for outdated Python packages using pip."""
    logging.info("Checking for outdated Python packages...")
    try:
        result = subprocess.run(['pip', 'list', '--outdated', '--format=json'], capture_output=True, text=True, check=True)
        outdated_packages = json.loads(result.stdout)

        if outdated_packages:
            for pkg in outdated_packages:
                findings["outdated_packages"].append(f"Package: {pkg['name']}, Current Version: {pkg['version']}, Latest Version: {pkg['latest_version']}")
        else:
            findings["outdated_packages"].append("No outdated packages found.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error fetching outdated packages: {e.stderr}")

# Function to check CVEs using the NVD API
def check_cves(package_name: str) -> None:
    """Check for known CVEs for the specified package."""
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keyword={package_name}&resultsPerPage=5"

    try:
        response = requests.get(nvd_url)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("vulnerabilities", [])

        if cve_items:
            for item in cve_items:
                cve_id = item['cve']['CVE_data_meta']['ID']
                description = item['cve']['description']['description_data'][0]['value']
                findings["cve_findings"].append(f"Vulnerability Found for {package_name}: {cve_id} - {description}")
        else:
            findings["cve_findings"].append(f"No CVEs found for {package_name}.")

    except requests.RequestException as e:
        logging.error(f"Error fetching CVE data for {package_name}: {str(e)}")

# Function to detect hard-coded secrets in source code
def check_hard_coded_secrets(directory: str) -> None:
    """Check for hard-coded secrets in the specified directory."""
    check_files_with_regex(directory, SECRET_PATTERNS_HARDCODED, {'.py', '.js', '.env', '.config'}, "secrets_found")

# Function to check for risky file permissions
def check_file_permissions(directory: str) -> None:
    """Check for files with risky permissions in the specified directory."""
    logging.info("Checking for files with risky permissions...")
    risky_permissions = []

    for filepath in Path(directory).rglob('*'):
        if filepath.is_file() and oct(filepath.stat().st_mode)[-3:] in {'777', '775', '766'}:  # Check for world-writable files
            risky_permissions.append(str(filepath))

    if risky_permissions:
        for file in risky_permissions:
            findings["risky_permissions"].append(f"Risky permissions found in: {file}")
    else:
        findings["risky_permissions"].append("No risky file permissions detected.")

# Functions to check for vulnerabilities using defined regex patterns
def check_sql_injections(directory: str) -> None:
    """Check for potential SQL injection patterns in source code."""
    check_files_with_regex(directory, SQL_PATTERNS, {'.py', '.php', '.js', '.html', '.sql'}, "sql_injections")

def check_xss_vulnerabilities(directory: str) -> None:
    """Check for potential XSS vulnerabilities in source code."""
    check_files_with_regex(directory, XSS_PATTERNS, {'.js', '.html', '.php'}, "xss_vulnerabilities")

def check_weak_cryptographic_algorithms(directory: str) -> None:
    """Check for the use of weak cryptographic algorithms."""
    check_files_with_regex(directory, WEAK_CRYPTO_PATTERNS, {'.py', '.js', '.config', '.txt'}, "weak_cryptographic_algorithms")

# Function to check for insecure HTTP headers
def check_insecure_http_headers(url: str) -> None:
    """Check for insecure HTTP headers by making a request to the specified URL."""
    logging.info(f"Checking for insecure HTTP headers at: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for bad responses
        headers = response.headers
        
        for header in HTTP_HEADERS:
            if header not in headers:
                findings["insecure_http_headers"].append(f"Missing header: {header}")

        if not findings["insecure_http_headers"]:
            findings["insecure_http_headers"].append("All recommended HTTP headers are present.")
    except requests.Timeout:
        logging.error(f"Request to '{url}' timed out.")
    except requests.ConnectionError:
        logging.error(f"Connection error occurred while trying to reach '{url}'.")
    except requests.RequestException as e:
        logging.error(f"Error fetching HTTP headers from '{url}': {e}")

# Generate a summary report of findings
def generate_report(report_file: str = 'vulnerability_report.txt') -> None:
    """Generate a summary report of the findings."""
    logging.info(f"Generating vulnerability report: {report_file}")
    with open(report_file, 'w') as file:
        file.write("Vulnerability Check Results\n")
        file.write("=============================\n\n")

        # Writing findings to report
        for category, findings_list in findings.items():
            file.write(f"{category.replace('_', ' ').title()}:\n")
            if findings_list:
                for finding in findings_list:
                    file.write(f"  - {finding}\n")
            else:
                file.write("  - No issues detected.\n")
            file.write("\n")

# Main function to run all checks
def run_checks(directory: str, url: str = None) -> None:
    """Run all vulnerability checks on the specified directory."""
    validate_directory(directory)  # Validate the directory before starting checks
    logging.info("Starting vulnerability checks...")
    check_outdated_packages()
    check_hard_coded_secrets(directory)
    check_file_permissions(directory)
    check_sql_injections(directory)
    check_xss_vulnerabilities(directory)
    check_weak_cryptographic_algorithms(directory)

    if url:
        check_insecure_http_headers(url)
    else:
        logging.warning("No URL provided for HTTP header check.")

    # Generate a final report after running all checks
    generate_report()

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run security checks on your codebase.")
    parser.add_argument('directory', help="Directory to scan for vulnerabilities.")
    parser.add_argument('url', help="URL to check for insecure HTTP headers.")
    
    args = parser.parse_args()
    print(args)  # This will show you the parsed arguments

    run_checks(args.directory, args.url)
