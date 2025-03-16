Below is a sample `README.md` file for your GitHub repository based on the provided Python script (`CryptoMaster`). This README includes an introduction, features, installation instructions, usage examples, and other relevant sections formatted in Markdown. I've tailored it to reflect the functionality of your script.

---

# CryptoMaster v9.0

**CryptoMaster** is an advanced, multi-pass encryption and decryption suite written in Python. It offers a variety of cryptographic algorithms, hybrid and layered encryption methods, brute-force decryption capabilities, and password generation tools. Designed for security enthusiasts and developers, this tool provides a robust platform for encrypting sensitive data and cracking encrypted files efficiently.

## Features

- **Multiple Encryption Methods**: Supports AES-256-GCM, ChaCha20-Poly1305, Fernet, RSA-8192, ECC (SECP521R1), TripleDES, Twofish, and more.
- **Hybrid Encryption**: Combines AES-256-GCM with RSA-8192 for enhanced security.
- **Layered Encryption**: Implements multi-layer encryption with AES, ChaCha20, Twofish, ECC (optional), and RSA.
- **Multi-Password Key Derivation**: Uses PBKDF2HMAC with SHA-512 and multiple passwords for key generation.
- **Decryption Tools**: Supports decryption with manual key entry or advanced multi-key methods.
- **Fast Brute-Force**: Integrates Hashcat for GPU-accelerated cracking and fallback CPU-based brute-forcing.
- **Password Generator**: Generates secure random passwords or exhaustive password lists.
- **Rich Interface**: Features a colorful CLI with `rich` library for enhanced user experience.

## Installation

### Prerequisites
- **Python 3.8+**
- **Hashcat** (optional, for fast brute-force decryption)
- A Unix-like system (Linux/macOS) is recommended; Windows may require additional setup.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/cryptomaster.git
   cd cryptomaster
   ```

2. **Install Dependencies**:
   Install the required Python packages using pip:
   ```bash
   pip install -r requirements.txt
   ```
   Create a `requirements.txt` file with:
   ```
   cryptography
   pyfiglet
   rich
   psutil
   twofish
   ```

3. **Install Hashcat (Optional)**:
   On Ubuntu/Debian:
   ```bash
   sudo apt install hashcat
   ```
   On macOS (via Homebrew):
   ```bash
   brew install hashcat
   ```

4. **Run the Script**:
   ```bash
   python3 cryptomaster.py
   ```

## Usage

Run the script and choose from the main menu:

```plaintext
Choose a category:
1. Encryption Tool
2. Decryption Tool
3. Advanced Multi-Key Decryption
4. Password Generate Tool
5. Decryption Fast Tool
6. Check Stored Passwords
7. Exit
```

### Examples

#### 1. Encrypt Data
- Select `1` from the menu.
- Enter data and three passwords.
- Choose an encryption method (e.g., `9` for Layered v9.0).
- Save the encrypted output to a file.

#### 2. Decrypt Data
- Select `2` from the menu.
- Provide the encrypted file path and passwords.
- Enter RSA/ECC key passwords if applicable.

#### 3. Brute-Force Decryption
- Select `5` for Decryption Fast Tool.
- Provide the encrypted file and a wordlist.
- Optionally use GPU acceleration with Hashcat.

#### 4. Generate Passwords
- Select `4` from the menu.
- Choose random or exhaustive generation.
- Specify length and character sets.

## File Structure
- `cryptomaster.py`: Main script with all functionality.
- `encrypted.bin`: Default output file for encrypted data.
- `passwords.txt`: Default output for generated passwords.
- `*.pem`: RSA/ECC key files generated during encryption.

## Security Notes
- Use strong, unique passwords for encryption.
- Store private keys securely and never share them.
- The brute-force tool is for educational purposes only; use responsibly.

## Contributing
Feel free to fork this repository, submit issues, or create pull requests. Contributions to improve security, add features, or optimize performance are welcome!

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Built with [cryptography](https://cryptography.io/), [rich](https://github.com/Textualize/rich), and [twofish](https://pypi.org/project/twofish/).
- Inspired by the need for a versatile, open-source encryption tool.

---

### Steps to Add to GitHub
1. **Create a Repository**:
   - Go to GitHub, click "New Repository," name it (e.g., `cryptomaster`), and initialize it with a README if desired.

2. **Add the README.md**:
   - Copy the above content into a file named `README.md` in your project directory.
   - Replace `yourusername` in the clone URL with your GitHub username.

3. **Commit and Push**:
   ```bash
   git add README.md cryptomaster.py
   git commit -m "Initial commit with README and script"
   git remote add origin https://github.com/yourusername/cryptomaster.git
   git push -u origin main
   ```

4. **Add requirements.txt**:
   - Create a `requirements.txt` file with the listed dependencies and push it to the repository.

This README provides a professional and comprehensive overview of your project, making it easy for others to understand and use your tool on GitHub! Let me know if you'd like any adjustments.