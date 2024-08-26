import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
from authentication import authenticate_user, create_user
from caesar_cipher import caesar_encrypt, caesar_decrypt
from aes_encryption import aes_encrypt, aes_decrypt, generate_aes_key
from rsa_encryption import rsa_encrypt, rsa_decrypt, generate_rsa_keys, save_key, load_key
from logger import setup_logger, log_activity
import pyperclip

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography System")
        self.root.geometry("700x700")
        self.root.configure(bg="#282C34")
        setup_logger()
        self.main_menu()
        
        

    def main_menu(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="Secure Message Encryption and Decryption System", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.auth_button = tk.Button(self.root, text="Authenticate", command=self.authenticate_user, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.auth_button.pack(pady=10)

        self.create_user_button = tk.Button(self.root, text="Create User", command=self.create_user, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.create_user_button.pack(pady=10)

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def authenticate_user(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="Authenticate", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.username_label = tk.Label(self.root, text="Username:", bg="#282C34", fg="#61AFEF")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.root, text="Password:", bg="#282C34", fg="#61AFEF")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30, relief="solid", borderwidth=2)
        self.password_entry.pack(pady=5)
        
        self.login_button = tk.Button(self.root, text="Login", command=self.check_credentials, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.login_button.pack(pady=10)
        
        self.back_button = tk.Button(self.root, text="Back to Main Menu", command=self.main_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.back_button.pack(pady=10)

    def create_user(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="Create User", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.username_label = tk.Label(self.root, text="Create Username:", bg="#282C34", fg="#61AFEF")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.username_entry.pack(pady=5)
        
        self.password_label = tk.Label(self.root, text="Create Password:", bg="#282C34", fg="#61AFEF")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30, relief="solid", borderwidth=2)
        self.password_entry.pack(pady=5)
        
        self.create_button = tk.Button(self.root, text="Create User", command=self.register_user, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.create_button.pack(pady=10)
        
        self.back_button = tk.Button(self.root, text="Back to Main Menu", command=self.main_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.back_button.pack(pady=10)

    def check_credentials(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if authenticate_user(username, password):
            messagebox.showinfo("Login Successful", "Welcome to the Cryptography System!")
            self.crypto_menu()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials. Please try again.")
            self.authenticate_user()

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        create_user(username, password)
        messagebox.showinfo("User Created", "User created successfully!")
        self.main_menu()

    def crypto_menu(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="Choose an Encryption Method", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.caesar_button = tk.Button(self.root, text="Caesar Cipher", command=self.caesar_cipher_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.caesar_button.pack(pady=10)

        self.aes_button = tk.Button(self.root, text="AES Encryption", command=self.aes_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.aes_button.pack(pady=10)

        self.rsa_button = tk.Button(self.root, text="RSA Encryption", command=self.rsa_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.rsa_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back to Main Menu", command=self.main_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.back_button.pack(pady=10)

    def caesar_cipher_menu(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="Caesar Cipher", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.text_label = tk.Label(self.root, text="Enter Text:", bg="#282C34", fg="#61AFEF")
        self.text_label.pack(pady=5)
        self.text_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.text_entry.pack(pady=5)
        
        self.shift_label = tk.Label(self.root, text="Enter Shift Value:", bg="#282C34", fg="#61AFEF")
        self.shift_label.pack(pady=5)
        self.shift_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.shift_entry.pack(pady=5)

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.caesar_encrypt, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.encrypt_button.pack(pady=10)
        
        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.caesar_decrypt, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.decrypt_button.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=50, height=10, relief="solid", borderwidth=2)
        self.result_text.pack(pady=20)

        self.copy_button = tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard, width=20, bg="#98C379", fg="#282C34", relief="ridge", borderwidth=2)
        self.copy_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back to Crypto Menu", command=self.crypto_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.back_button.pack(pady=10)

    def aes_menu(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="AES Encryption", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.text_label = tk.Label(self.root, text="Enter Text:", bg="#282C34", fg="#61AFEF")
        self.text_label.pack(pady=5)
        self.text_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.text_entry.pack(pady=5)
        
        self.key_label = tk.Label(self.root, text="Enter Key (16 chars) or leave blank to auto-generate:", bg="#282C34", fg="#61AFEF")
        self.key_label.pack(pady=5)
        self.key_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.key_entry.pack(pady=5)

        self.auto_key_button = tk.Button(self.root, text="Auto-Generate Key", command=self.auto_generate_aes_key, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.auto_key_button.pack(pady=10)

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.aes_encrypt, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.aes_decrypt, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.decrypt_button.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=50, height=10, relief="solid", borderwidth=2)
        self.result_text.pack(pady=20)

        self.copy_button = tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard, width=20, bg="#98C379", fg="#282C34", relief="ridge", borderwidth=2)
        self.copy_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back to Crypto Menu", command=self.crypto_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.back_button.pack(pady=10)

    def rsa_menu(self):
        self.clear_frame()
        self.label = tk.Label(self.root, text="RSA Encryption", font=("Arial", 16, 'bold'), bg="#282C34", fg="#61AFEF")
        self.label.pack(pady=20)

        self.text_label = tk.Label(self.root, text="Enter Text:", bg="#282C34", fg="#61AFEF")
        self.text_label.pack(pady=5)
        self.text_entry = tk.Entry(self.root, width=30, relief="solid", borderwidth=2)
        self.text_entry.pack(pady=5)

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.rsa_encrypt_text, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.rsa_decrypt_text, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.decrypt_button.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=50, height=10, relief="solid", borderwidth=2)
        self.result_text.pack(pady=20)

        self.copy_button = tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard, width=20, bg="#98C379", fg="#282C34", relief="ridge", borderwidth=2)
        self.copy_button.pack(pady=10)

        self.generate_keys_button = tk.Button(self.root, text="Generate RSA Keys", command=self.generate_keys, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.generate_keys_button.pack(pady=10)

        self.back_button = tk.Button(self.root, text="Back to Crypto Menu", command=self.crypto_menu, width=20, bg="#61AFEF", fg="#282C34", relief="ridge", borderwidth=2)
        self.back_button.pack(pady=10)

    def copy_to_clipboard(self):
        text = self.result_text.get(1.0, tk.END).strip()
        if text:
            pyperclip.copy(text)
            messagebox.showinfo("Copied", "Text copied to clipboard!")

    def caesar_encrypt(self):
        try:
            text = self.text_entry.get()
            shift = int(self.shift_entry.get())
            encrypted_text = caesar_encrypt(text, shift)
            self.update_result_text(encrypted_text)
            log_activity(f"Caesar Cipher Encryption: {text} -> {encrypted_text}")
        except ValueError:
            messagebox.showerror("Input Error", "Shift value must be an integer.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during Caesar encryption: {str(e)}")

    def caesar_decrypt(self):
        try:
            text = self.text_entry.get()
            shift = int(self.shift_entry.get())
            decrypted_text = caesar_decrypt(text, shift)
            self.update_result_text(decrypted_text)
            log_activity(f"Caesar Cipher Decryption: {text} -> {decrypted_text}")
        except ValueError:
            messagebox.showerror("Input Error", "Shift value must be an integer.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during Caesar decryption: {str(e)}")

    def aes_encrypt(self):
        try:
            text = self.text_entry.get()
            key = self.key_entry.get()
            if not key:
                key = generate_aes_key()
                messagebox.showinfo("Key Generated", f"No key provided. Generated key: {key}")
                self.key_entry.insert(0, key)
            elif len(key) != 16:
                messagebox.showerror("Key Error", "Key must be 16 characters long.")
                return
            encrypted_text = aes_encrypt(text, key)
            self.update_result_text(encrypted_text)
            log_activity(f"AES Encryption: {text} -> {encrypted_text}")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during AES encryption: {str(e)}")

    def aes_decrypt(self):
        try:
            text = self.text_entry.get()
            key = self.key_entry.get()
            if len(key) != 16:
                messagebox.showerror("Key Error", "Key must be 16 characters long.")
                return
            decrypted_text = aes_decrypt(text, key)
            self.update_result_text(decrypted_text)
            log_activity(f"AES Decryption: {text} -> {decrypted_text}")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during AES decryption: {str(e)}")

    def rsa_encrypt_text(self):
        try:
            text = self.text_entry.get()
            public_key_data = load_key("public.pem")
            if public_key_data is None:
                messagebox.showerror("Key Error", "Public key not found.")
                return
            encrypted_text = rsa_encrypt(text, public_key_data)
            self.update_result_text(encrypted_text)
            log_activity(f"RSA Encryption: {text} -> {encrypted_text}")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during RSA encryption: {str(e)}")

    def rsa_decrypt_text(self):
        try:
            text = self.text_entry.get()
            private_key_data = load_key("private.pem")
            if private_key_data is None:
                messagebox.showerror("Key Error", "Private key not found.")
                return
            decrypted_text = rsa_decrypt(text, private_key_data)
            self.update_result_text(decrypted_text)
            log_activity(f"RSA Decryption: {text} -> {decrypted_text}")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during RSA decryption: {str(e)}")

    def generate_keys(self):
        try:
            private_key, public_key = generate_rsa_keys()
            save_key(private_key, "private.pem")
            save_key(public_key, "public.pem")
            messagebox.showinfo("Keys Generated", "RSA keys have been generated and saved.")
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"An error occurred while generating keys: {str(e)}")

    def auto_generate_aes_key(self):
        key = generate_aes_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        messagebox.showinfo("Key Generated", f"Auto-generated AES key: {key}")

    def update_result_text(self, text):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
