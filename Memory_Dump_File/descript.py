import base64
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate an AES key from the given password and salt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,  # Increased cost parameter
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def decrypt_password(encrypted_password: str, key: bytes, salt: bytes) -> str:
    """Decrypt the encrypted password using the given key."""
    encrypted_data = base64.b64decode(encrypted_password)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_password = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    password = unpadder.update(padded_password) + unpadder.finalize()
    return password.decode('utf-8')

# Main function
def main():
    encrypted_passwords = [
        "/aZy8tWe2TK4lJ/kR1iXu1Ra9lDi9UABUFb2jwSdH1xJo+H9J93ySBKKHQjiBsA4QFJSEIi1yoEJaQ7CXdqJnA==",
        "TrMXNs9T++O7v8KIwkG+Kqh34uGDxT+vM9P7XuSPgnzaYd7CNW0H5su8dXS4lQFBUyB8P8oNN2GOQ5gTKYGupA==",
        "OvbJvKe0r5/ap0a16kC4XrtPsZzZes5B8+M0VFQ+H2hmy/nZ6igSAFcEvSRkex5G8ThGFrlxnUCuyoQrHidu4w==",
        "MJUSlegdkPdmIIZ4pbXdWXWJfEH3IgPd3BghGTn/KgrxpU4NxXmE7cJS/yDonToM8E2eWBLN8p5V9pKNsljvRQ==",
        "OrGLJsSnNvp1vgKxRbqhZzJ6o07PZYsTldNzpILSq1WwkGUSpDfxSD24WDFMBjeZPM7DisZAzXH/aR2blrxTBQ=="
    ]
    salts = [
        base64.b64decode("Wn9rldgC9bHNOqyPMZeuug=="),
        base64.b64decode("vvP7Lmx8xKmwRRDUMenqNA=="),
        base64.b64decode("Z/c1exFQShsdT06dmBlw7A=="),
        base64.b64decode("neTSmaO4NBBpEfoQiAZVQA=="),
        base64.b64decode("+Bhd39YsCbSPgik2E02hoQ==")
    ]

    key = input("Enter the key: ")

    for encrypted_password, salt in zip(encrypted_passwords, salts):
        try:
            # Generate key from entered key and salt
            derived_key = generate_key(key, salt)

            # Decrypt the password
            decrypted_password = decrypt_password(encrypted_password, derived_key, salt)
            print(f"Possible password: {decrypted_password}")
        except Exception as e:
            print(f"Error decrypting password for one of the entries: {e}")

if __name__ == "__main__":
    main()
