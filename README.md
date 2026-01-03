# 🔍 NexRecon

**Advanced OSINT & Reconnaissance Toolkit**

A comprehensive command-line utility for information gathering, network analysis, and security assessment.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

---

## ✨ Features

### 🌐 Network & IP Tools
| Tool | Description |
|------|-------------|
| **IP Tracker** | Geolocate any IP address (country, city, ISP, coordinates) |
| **Show Your IP** | Display your public IP address |
| **Port Scanner** | Scan common ports on target hosts |
| **Subnet Calculator** | Calculate network ranges, broadcast addresses, host counts |

### 🔎 OSINT & Lookup
| Tool | Description |
|------|-------------|
| **Phone Tracker** | Lookup phone number details (carrier, location, timezone) |
| **Username Search** | Find social media profiles across 20+ platforms |
| **WHOIS Lookup** | Get domain registration information |
| **DNS Lookup** | Query DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) |

### 🛡️ Security & Analysis
| Tool | Description |
|------|-------------|
| **Header Analysis** | Check website security headers (HSTS, CSP, XSS protection) |
| **Image EXIF** | Extract metadata from images (GPS, camera info, timestamps) |

### 🔧 Utilities
| Tool | Description |
|------|-------------|
| **Password Generator** | Generate cryptographically secure passwords |
| **Hash Tools** | Generate MD5/SHA hashes or identify hash types |

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/nexrecon.git
cd nexrecon

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Manual Installation

```bash
pip install requests phonenumbers Pillow
```

---

## 🚀 Usage

### Run the tool

```bash
python hacker.py
```

### Quick Commands
| Command | Action |
|---------|--------|
| `1-12` | Select a tool |
| `h` or `?` | Show help |
| `q` or `0` | Exit |
| `Ctrl+C` | Cancel operation |

---

## 📸 Screenshots

```
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║    ███╗   ██╗███████╗██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗  ║
    ║    ████╗  ██║██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║  ║
    ║    ██╔██╗ ██║█████╗   ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║  ║
    ║    ██║╚██╗██║██╔══╝   ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ║
    ║    ██║ ╚████║███████╗██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║  ║
    ║    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  ║
    ║                                                                   ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║  👤 Author: Kumar Devashish    📌 Version: 3.0                    ║
    ║  🔧 Tools: 12                  🌐 Advanced OSINT Toolkit          ║
    ╚═══════════════════════════════════════════════════════════════════╝
```

---

## 🛠️ Tool Details

### 1. IP Tracker
Track geolocation information for any IP address:
- Country, City, Region
- ISP & Organization
- Latitude/Longitude with Google Maps link
- Timezone information
- VPN/Proxy detection

### 2. Phone Number Tracker
Analyze phone numbers worldwide:
- Carrier/Operator identification
- Geographic location
- Number validation
- International formatting
- Timezone detection

### 3. Username Search
Search for usernames across platforms:
- Facebook, Instagram, Twitter/X
- GitHub, LinkedIn, Reddit
- TikTok, YouTube, Twitch
- And 15+ more platforms

### 4. Image Metadata Extractor
Extract EXIF data from images:
- 📍 GPS coordinates (with privacy warning)
- 📷 Camera make/model
- ⏰ Date/time taken
- 🔧 Exposure settings
- 💻 Software used

---

## ⚠️ Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. 

- Always obtain proper authorization before scanning or gathering information
- Respect privacy and legal boundaries
- The author is not responsible for any misuse of this tool
- Use responsibly and ethically

---

## 📋 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `requests` | ≥2.28.0 | HTTP requests |
| `phonenumbers` | ≥8.13.0 | Phone number parsing |
| `Pillow` | ≥9.0.0 | Image processing |

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Kumar Devashish**

- GitHub: [@kumardevashish](https://github.com/kumardevashish)

---

## 🌟 Show Your Support

Give a ⭐ if this project helped you!

---

## 📝 Changelog

### Version 1.0.0 (January 2026)
- ✨ New categorized menu interface
- 🎨 Improved UI with animations
- 🔒 Added Port Scanner
- 🧮 Added Subnet Calculator
- 🖼️ Added Image Metadata Extractor
- 🔑 Added Password Generator
- #️⃣ Added Hash Tools
- 🌐 Improved WHOIS with multiple API fallbacks
- 🐛 Better error handling throughout


