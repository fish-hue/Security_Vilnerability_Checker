import hashlib

# Example of weak cryptographic algorithm
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash

print(hash_password("mypassword"))
