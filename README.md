# 🔍 JS Secret Hunter Pro

A powerful, low-noise JavaScript secret scanner built for **bug bounty hunters, penetration testers, and security researchers**.

JS Secret Hunter Pro helps identify exposed secrets such as API keys, tokens, credentials, and sensitive configurations from JavaScript files.

---

## 🚀 Key Features

* 🔎 Scans JavaScript files (remote & local)
* 🔐 Detects API keys, tokens, credentials, and secrets
* ⚡ Fast and lightweight scanning
* 🎯 Multiple scan modes (strict, balanced, aggressive)
* 🧠 Smart validation (JWT, Basic Auth, MongoDB URI, private keys, etc.)
* 🔓 Option to show full values (no masking)
* 🧾 JSON output support
* 🔍 Verbose mode for debugging
* 🚫 Option to skip or include noisy bundles

---

## 🧩 Supported Secret Types

* API Keys (Google, AWS, etc.)
* JWT Tokens (with decoding support)
* Bearer Tokens
* Authorization Headers (Basic Auth)
* OAuth Tokens
* Firebase Keys
* MongoDB Connection URIs
* Hardcoded Credentials
* Private Keys (partial detection)
* Secrets in JavaScript variables

---

## 📦 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/suvendu-dash/js-secret-hunter-pro.git
cd js-secret-hunter-pro
```

---

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available:

```bash
pip install requests
```

---

## ⚙️ Input Format (Important)

This tool works with an **input file** containing JavaScript sources.

Example file: `jsfiles.txt`

```text
https://target.com/app.js
https://cdn.target.com/main.js
/home/user/files/test.js
```

👉 Supports:

* Remote JS URLs
* Local JavaScript files

---

## ⚙️ Usage

### 🔹 Basic Command

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt
```

---

## ⚙️ Scan Modes

### 🔹 1. Strict Mode (Recommended)

Best for bug bounty — low noise, high accuracy.

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt --mode strict
```

---

### 🔹 2. Balanced Mode

Moderate detection with some extra coverage.

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt --mode balanced
```

---

### 🔹 3. Aggressive Mode

Maximum detection (may include false positives).

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt --mode aggressive
```

---

## ⚙️ Output Options

### 🔹 Save Output to File

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt -o result.txt
```

---

### 🔹 JSON Output

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt --json result.json
```

---

## ⚙️ Advanced Options

### 🔹 Show Full Secrets (No Masking)

```bash
--no-mask
```

---

### 🔹 Decode JWT Tokens

```bash
--decode-jwt
```

---

### 🔹 Verbose Mode

```bash
--verbose
```

---

### 🔹 Include Noisy Bundles

```bash
--allow-noisy-bundles
```

---

### 🔹 Timeout Control

```bash
--timeout 10
```

---

### 🔹 Limit Lines per File

```bash
--max-lines 2000
```

---

## 🚀 Recommended Bug Bounty Command

Use this for most real-world scenarios:

```bash
python3 js_secret_hunter_pro.py -i jsfiles.txt -o clean_result.txt --mode strict --no-mask --decode-jwt --verbose
```

---

## 📌 Example Output

```text
[+] Scanning: https://target.com/app.js

[!] API Key Found:
AIzaSyXXXXXX...

[!] JWT Token Found:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

[+] Scan Completed
```

---

## 🧠 How It Works

1. Reads input file (`jsfiles.txt`)
2. Fetches JS content (local or remote)
3. Applies regex-based detection engine
4. Validates findings (JWT, credentials, etc.)
5. Outputs results in text or JSON format

---

## 🎯 Use Cases

* Bug bounty reconnaissance
* JavaScript security analysis
* Secret exposure detection
* Red team recon workflows
* Automation pipelines

---

## ⚠️ Limitations

* Static analysis only (no JS execution)
* Possible false positives (especially aggressive mode)
* Depends on regex patterns

---

## 🔐 Ethical Usage Disclaimer

This tool is intended for:

* Authorized penetration testing
* Bug bounty programs
* Educational purposes

❌ Do NOT use on unauthorized targets
❌ Misuse may lead to legal consequences

---

## 🛠️ Tech Stack

* Python 3
* Requests
* Regex

---

## 📂 Project Structure

```
js-secret-hunter-pro/
├── js_secret_hunter_pro.py
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
```

---

## 🧑‍💻 Author

**Suvendu Dash**
Cybersecurity Professional | Pentester | Bug Bounty Hunter

---

## 🌟 Future Improvements

* Automatic JS extraction from websites
* Bulk domain scanning
* Multi-threaded scanning
* Advanced secret pattern detection
* CLI enhancements
* Integration with recon tools

---

## 🤝 Contribution

Contributions are welcome!

1. Fork the repository
2. Create a new branch
3. Commit changes
4. Submit a pull request

---

## ⭐ Support

If you find this tool useful:

* Star the repository ⭐
* Share with the community
* Contribute improvements

---

## 📜 License

MIT License

---

## 📢 Final Note

Built for the **bug bounty and cybersecurity community**.

Use responsibly. Hack ethically. 🔐
