# PDF Threat Scanner

[![PyPI version](https://img.shields.io/pypi/v/pdf-threat-scanner.svg)](https://pypi.org/project/pdf-threat-scanner)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)  
[![Python versions](https://img.shields.io/pypi/pyversions/pdf-threat-scanner.svg)](https://pypi.org/project/pdf-threat-scanner)

A modern, user-friendly desktop application to scan PDF files for potential threats and risky features. Built with PyQt5 for a smooth GUI experience and DidierStevens’ `pdfid.py` for deep PDF analysis.

---

## 📋 Table of Contents

- [✨ Features](#-features)  
- [🚀 Quick Start](#-quick-start)  
  - [Prerequisites](#prerequisites)  
  - [Installation](#installation)  
- [⚙️ Usage](#️-usage)  
- [🛠️ Configuration](#️-configuration)  
- [📦 Installers](#-installers)  
- [📊 Threat Levels](#-threat-levels)  
- [⚙️ Advanced](#️-advanced)  
- [🤝 Contributing](#-contributing)  
- [📄 License](#-license)  
- [✉️ Contact](#️-contact)

---

## ✨ Features

- **Drag & Drop** or **Browse** for PDF files  
- **Real-time** threat scanning with progress bar  
- **Color-coded** threat-level cards (Safe → Critical)  
- **Detailed** PDF structure breakdown on demand  
- **Export** scan results to JSON  
- **History** panel to revisit past scans  
- **MVC-based** code architecture for easy extension  
- **Cross-platform**: Windows, macOS, Linux  

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ (if running source code)  
- [pdfid.py](https://github.com/DidierStevens/DidierStevensSuite) by Didier Stevens  

### Installation

You can either run the program from source or install one of the prebuilt binaries below.

---

## 📦 Installers

For easy installation, prebuilt installers are available for the most popular platforms:

- **Windows:** `pdf-threat-scanner-x.y.z.exe`  
- **Debian/Ubuntu:** `pdf-threat-scanner-x.y.z.deb`  
- **Fedora/RedHat:** `pdf-threat-scanner-x.y.z.rpm`

Download the latest installer from the [Releases](https://github.com/ErfanNahidi/pdf_scanner/releases) page and follow your OS’s standard installation procedure.

---

## ⚙️ Usage

### From Source

1. Clone the repo and install dependencies:
   ```bash
   git clone https://github.com/ErfanNahidi/pdf_scanner.git
   cd pdf_scanner
   pip install -r requirements.txt
    ````

2. Download or place `pdfid.py` in the `pdfid/pdfid/` folder.
3. Run the GUI:

   ```bash
   python gui.py
   ```

### From Installer

* Launch the installed application from your OS menu or desktop shortcut.
* Use drag & drop or browse to scan PDF files for threats.

---

## 🛠️ Configuration

* Scan timeout, logging levels, and custom threat rules can be adjusted in the `backend.py` file.
* Add new detection rules by subclassing `ThreatRule` in `backend.py`.

---

## 📊 Threat Levels

| Level        | Description                                         |
| ------------ | --------------------------------------------------- |
| **SAFE**     | No suspicious elements found                        |
| **LOW**      | Harmless anomalies (e.g., metadata quirks)          |
| **MEDIUM**   | Potentially unwanted features (e.g., JavaScript)    |
| **HIGH**     | Dangerous constructs (e.g., embedded executables)   |
| **CRITICAL** | Severe threats — avoid opening without verification |

---

## ⚙️ Advanced

* Build standalone executables with [PyInstaller](https://www.pyinstaller.org/)
* Extend scanning rules by editing `backend.py`
* Integrate CLI functionality if needed

---

## 🤝 Contributing

Contributions are very welcome!

1. Fork this repo
2. Create a feature branch: `git checkout -b feature/YourFeature`
3. Commit your changes: `git commit -m "Add new feature"`
4. Push the branch: `git push origin feature/YourFeature`
5. Open a Pull Request — I’ll review it with ❤️

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## ✉️ Contact

Erfan Nahidi • \[[erfannahidi20@gmail.com](erfannahidi20@gmail.com)]
Feel free to reach out with questions, feedback, or just to say hi!
