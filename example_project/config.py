# Example of bad file permissions
import os

# Set risky file permissions on a sensitive file
os.chmod('sensitive_data.txt', 0o777)  # World-writable permissions
