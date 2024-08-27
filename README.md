# Secure-Message-Encryption-and-Decryption-System

This project is a Python-based encryption tool that uses AES, RSA, and Caesar Cipher encryption algorithms. It features a graphical user interface (GUI) built with Tkinter, allowing users to easily encrypt and decrypt messages. The project also includes functionalities for key management and error handling.

## Features

- **AES Encryption**: Encrypt and decrypt text using the AES algorithm with a 16-character key. You can generate a key automatically or provide your own.
- **RSA Encryption**: Encrypt and decrypt text using RSA encryption with key generation and management.
- **Caesar Cipher**: Simple text encryption and decryption using Caesar Cipher.
- **Copy Functionality**: Easily copy encrypted and decrypted messages to the clipboard.
- **User Authentication**: Password hashing and authentication with SHA-256.
- **Beautiful GUI**: A Tkinter GUI with borders, colors, and resizable windows for a better user experience.

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/cryptography-project.git
    cd cryptography-project
    ```

2. **Create a Virtual Environment** (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install Required Packages**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the Application**:
    ```bash
    python gui.py
    ```

2. **Using the Application**:
   - Select the encryption method (AES, RSA, or Caesar Cipher) from the GUI.
   - Enter the text you want to encrypt or decrypt.
   - Provide the key if necessary, or generate one automatically for AES.
   - Click the respective button to encrypt or decrypt the text.
   - Copy the result to the clipboard using the "Copy" button.

## Encryption Methods

### AES (Advanced Encryption Standard)
- **Key Length**: 16 characters.
- **Modes**: ECB (Electronic Codebook).

### RSA (Rivest–Shamir–Adleman)
- **Key Generation**: Public and private keys are generated and can be saved/loaded.
- **Key Size**: Configurable in the code (commonly 2048 bits).

### Caesar Cipher
- **Shift**: User-defined shift for text encryption and decryption.

## Screenshots

_Add screenshots of your GUI here._

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the creators of the cryptography libraries used in this project.
- Inspired by various open-source cryptography projects.
