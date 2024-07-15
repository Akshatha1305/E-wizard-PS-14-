import os
import re
import hashlib
import uuid
import base64
import hmac
import time
import argparse
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.hmac import HMAC

# Constants
USER_DB_FILE = "/home/gat/intel/pass.txt"
RESET_TOKEN_FILE = "/home/gat/intel/reset.txt"
MAX_USERS = 20
LOCKOUT_TIME = 60 * 60  # 60 minutes in seconds

# Globals
failed_attempts = {}
lockout_timestamps = {}

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

def generate_hmac(key: bytes, data: bytes) -> bytes:
    """Generate an HMAC for the given data."""
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def encrypt_password(password: str, key: bytes) -> str:
    """Encrypt the password using the given key and append HMAC."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_password = padder.update(password.encode()) + padder.finalize()
    ct = encryptor.update(padded_password) + encryptor.finalize()
    
    # Append HMAC for integrity
    hmac_value = generate_hmac(key, iv + ct)
    encrypted_data = iv + ct + hmac_value
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    """Decrypt the encrypted password using the given key."""
    encrypted_data = base64.b64decode(encrypted_password)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:-32]
    hmac_value = encrypted_data[-32:]
    
    # Verify HMAC for integrity
    expected_hmac = generate_hmac(key, iv + ct)
    if not hmac.compare_digest(expected_hmac, hmac_value):
        raise ValueError("HMAC verification failed")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_password = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    password = unpadder.update(padded_password) + unpadder.finalize()
    return password.decode('utf-8')

def validate_password(password: str) -> bool:
    """Check if the password meets the required criteria."""
    if (len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(not c.isalnum() for c in password)):
        return True
    return False

def store_user(username: str, password: str, encrypted_password: str, salt: bytes):
    """Store the encrypted password and salt for the user."""
    try:
        with open(USER_DB_FILE, 'a') as f:
            f.write(f"{username},{encrypted_password},{base64.b64encode(salt).decode('utf-8')}\n")
    except PermissionError:
        fallback_file = "Password_fallback.txt"
        print(f"Warning: Could not write to {USER_DB_FILE}. Using fallback {fallback_file}.")
        with open(fallback_file, 'a') as f:
            f.write(f"{username},{encrypted_password},{base64.b64encode(salt).decode('utf-8')}\n")

def load_users() -> dict:
    """Load existing users and their encrypted passwords."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    
    users = {}
    with open(USER_DB_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) != 3:
                # Skip lines that do not have exactly 3 parts
                continue
            username, encrypted_password, salt = parts
            users[username] = (encrypted_password, base64.b64decode(salt))
    return users

def generate_reset_token(username: str) -> str:
    """Generate a secure token for password reset and store it temporarily."""
    token = str(uuid.uuid4())
    try:
        with open(RESET_TOKEN_FILE, 'a') as f:
            f.write(f"{username},{token}\n")
    except PermissionError:
        fallback_file = "reset_tokens_fallback.txt"
        print(f"Warning: Could not write to {RESET_TOKEN_FILE}. Using fallback {fallback_file}.")
        with open(fallback_file, 'a') as f:
            f.write(f"{username},{token}\n")
    return token

def validate_reset_token(username: str, token: str) -> bool:
    """Validate the reset token for the given username."""
    if not os.path.exists(RESET_TOKEN_FILE):
        return False
    
    valid = False
    with open(RESET_TOKEN_FILE, 'r') as f:
        lines = f.readlines()
    with open(RESET_TOKEN_FILE, 'w') as f:
        for line in lines:
            stored_username, stored_token = line.strip().split(',')
            if stored_username == username and stored_token == token:
                valid = True
            else:
                f.write(line)
    return valid

def encrypt_file(input_file: str, output_file: str, password: str):
    """Encrypts the input file using AES encryption with the given password."""
    try:
        with open(input_file, 'rb') as f:
            file_data = f.read()
    except Exception as e:
        print(f"Failed to read input file: {e}")
        return

    # Simulate language change by encoding to utf-8 (can be replaced with actual translation logic)
    try:
        file_data = file_data.decode('utf-8', errors='ignore').encode('utf-8')
    except Exception as e:
        print(f"Failed to encode file data: {e}")
        return

    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        # Append HMAC for integrity
        hmac_value = generate_hmac(key, iv + ct)
        encrypted_data = iv + ct + hmac_value

        with open(output_file, 'wb') as f:
            f.write(salt + encrypted_data)

        print(f"File encrypted successfully! Saved as: {output_file}")
    except Exception as e:
        print(f"File encryption failed: {e}")

def handle_failed_attempt(username):
    if username not in failed_attempts:
        failed_attempts[username] = 0
    failed_attempts[username] += 1

    if failed_attempts[username] >= 3:
        lockout_timestamps[username] = time.time()
        print("Too many failed attempts. Account locked for 60 minutes.")
    else:
        print("Invalid username or password")

def register_user(username, password):
    users = load_users()
    if not username or not password:
        print("Both fields are required")
        return

    if len(username) > 20:
        print("Username must be less than 20 characters")
        return

    if not validate_password(password):
        print("Password does not meet the criteria")
        return

    if username in users:
        print("Username already exists")
        return

    salt = os.urandom(16)
    key = generate_key(password, salt)
    encrypted_password = encrypt_password(password, key)

    store_user(username, password, encrypted_password, salt)
    print("User registered successfully")

def login_user(username, password):
    users = load_users()
    if not username or not password:
        print("Both fields are required")
        return

    if username not in users:
        print("Invalid username or password")
        return

    encrypted_password, salt = users[username]
    key = generate_key(password, salt)

    try:
        decrypted_password = decrypt_password(encrypted_password, key)
        if password == decrypted_password:
            print("Login successful")
        else:
            handle_failed_attempt(username)
    except Exception as e:
        handle_failed_attempt(username)

def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption System")
    parser.add_argument('--headless', action='store_true', help='Run in headless mode')
    parser.add_argument('--register', nargs=2, metavar=('username', 'password'), help='Register a new user')
    parser.add_argument('--login', nargs=2, metavar=('username', 'password'), help='Login as an existing user')
    parser.add_argument('--encrypt', nargs=3, metavar=('input_file', 'output_file', 'password'), help='Encrypt a file')

    args = parser.parse_args()

    if args.headless:
        if args.register:
            register_user(args.register[0], args.register[1])
        elif args.login:
            login_user(args.login[0], args.login[1])
        elif args.encrypt:
            encrypt_file(args.encrypt[0], args.encrypt[1], args.encrypt[2])
        else:
            parser.print_help()
    else:
        class UserAuthApp(tk.Tk):
            def __init__(self):
                super().__init__()
                self.title("File Encryption")
                self.configure(bg='black')
                self.geometry("800x600")
                self.users = load_users()

                self.create_widgets()

            def create_widgets(self):
                # Stylish title
                title = tk.Label(self, text="Secure File Encryption System", bg='black', fg='white', font=('Helvetica', 24, 'bold'))
                title.pack(pady=20)

                form_frame = tk.Frame(self, bg='black')
                form_frame.pack(pady=20)

                tk.Label(form_frame, text="Username:", bg='black', fg='white', font=('Helvetica', 14, 'bold')).grid(row=0, column=0, padx=10, pady=5, sticky='e')
                self.username_entry = tk.Entry(form_frame, font=('Helvetica', 14))
                self.username_entry.grid(row=0, column=1, padx=10, pady=5)

                tk.Label(form_frame, text="Password:", bg='black', fg='white', font=('Helvetica', 14, 'bold')).grid(row=1, column=0, padx=10, pady=5, sticky='e')
                self.password_entry = tk.Entry(form_frame, font=('Helvetica', 14), show='*')
                self.password_entry.grid(row=1, column=1, padx=10, pady=5)

                # Show Password Checkbox
                self.show_password_var = tk.IntVar()
                show_password_check = tk.Checkbutton(form_frame, text="Show Password", bg='black', fg='white', font=('Helvetica', 12), variable=self.show_password_var, command=self.toggle_password)
                show_password_check.grid(row=2, columnspan=2)

                button_frame = tk.Frame(self, bg='black')
                button_frame.pack(pady=20)

                tk.Button(button_frame, text="Register", command=self.register_user, font=('Helvetica', 14, 'bold'), bg='white', fg='black').grid(row=0, column=0, padx=10, pady=5)
                tk.Button(button_frame, text="Login", command=self.login_user, font=('Helvetica', 14, 'bold'), bg='white', fg='black').grid(row=0, column=1, padx=10, pady=5)
                tk.Button(button_frame, text="Forgot Password", command=self.forgot_password, font=('Helvetica', 14, 'bold'), bg='white', fg='black').grid(row=0, column=2, padx=10, pady=5)

                # Instructional text
                instructions = (
                    "Username should be unique and max 20 characters.\n"
                    "Password should be at least 8 characters long, contain:\n"
                    "1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character."
                )
                instruction_label = tk.Label(self, text=instructions, bg='black', fg='white', font=('Helvetica', 12))
                instruction_label.pack(pady=10)

            def toggle_password(self):
                if self.show_password_var.get():
                    self.password_entry.config(show='')
                else:
                    self.password_entry.config(show='*')

            def register_user(self):
                username = self.username_entry.get()
                password = self.password_entry.get()

                if not username or not password:
                    messagebox.showerror("Error", "Both fields are required")
                    return

                if len(username) > 20:
                    messagebox.showerror("Error", "Username must be less than 20 characters")
                    return

                if not validate_password(password):
                    messagebox.showerror("Error", "Password does not meet the criteria")
                    return

                if username in self.users:
                    messagebox.showerror("Error", "Username already exists")
                    return

                salt = os.urandom(16)
                key = generate_key(password, salt)
                encrypted_password = encrypt_password(password, key)

                store_user(username, password, encrypted_password, salt)
                self.users[username] = (encrypted_password, salt)

                messagebox.showinfo("Success", "User registered successfully")

            def login_user(self):
                username = self.username_entry.get()
                password = self.password_entry.get()

                if not username or not password:
                    messagebox.showerror("Error", "Both fields are required")
                    return

                if username not in self.users:
                    messagebox.showerror("Error", "Invalid username or password")
                    return

                encrypted_password, salt = self.users[username]
                key = generate_key(password, salt)

                try:
                    decrypted_password = decrypt_password(encrypted_password, key)
                    if password == decrypted_password:
                        self.show_encryption_options()
                    else:
                        handle_failed_attempt(username)
                except Exception as e:
                    handle_failed_attempt(username)

            def handle_failed_attempt(self, username):
                if username not in failed_attempts:
                    failed_attempts[username] = 0
                failed_attempts[username] += 1

                if failed_attempts[username] >= 3:
                    lockout_timestamps[username] = time.time()
                    messagebox.showerror("Error", "Too many failed attempts. Account locked for 60 minutes.")
                else:
                    messagebox.showerror("Error", "Invalid username or password")

            def show_encryption_options(self):
                self.clear_widgets()

                file_frame = tk.Frame(self, bg='black')
                file_frame.pack(pady=20)

                tk.Label(file_frame, text="Input File:", bg='black', fg='white', font=('Helvetica', 14, 'bold')).grid(row=0, column=0, padx=10, pady=5, sticky='e')
                self.input_file_entry = tk.Entry(file_frame, font=('Helvetica', 14))
                self.input_file_entry.grid(row=0, column=1, padx=10, pady=5)

                tk.Label(file_frame, text="Output File:", bg='black', fg='white', font=('Helvetica', 14, 'bold')).grid(row=1, column=0, padx=10, pady=5, sticky='e')
                self.output_file_entry = tk.Entry(file_frame, font=('Helvetica', 14))
                self.output_file_entry.grid(row=1, column=1, padx=10, pady=5)

                tk.Button(file_frame, text="Encrypt File", command=self.encrypt_selected_file, font=('Helvetica', 14, 'bold'), bg='white', fg='black').grid(row=2, columnspan=2, pady=20)

            def clear_widgets(self):
                for widget in self.winfo_children():
                    widget.destroy()

            def encrypt_selected_file(self):
                input_file = self.input_file_entry.get()
                output_file = self.output_file_entry.get()
                password = simpledialog.askstring("Password", "Enter your password:", show='*')

                if not input_file or not output_file or not password:
                    messagebox.showerror("Error", "All fields are required")
                    return

                encrypt_file(input_file, output_file, password)

            def forgot_password(self):
                username = self.username_entry.get()

                if not username:
                    messagebox.showerror("Error", "Username is required")
                    return

                if username not in self.users:
                    messagebox.showerror("Error", "Invalid username")
                    return

                token = generate_reset_token(username)
                messagebox.showinfo("Info", f"Reset token generated: {token}")

        app = UserAuthApp()
        app.mainloop()

if __name__ == "__main__":
    main()
