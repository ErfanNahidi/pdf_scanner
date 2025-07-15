# PDF Threat Scanner

![Version](https://img.shields.io/badge/Version-4.0.0-5865F2)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A modern, cross-platform desktop application designed to quickly analyze PDF files for potential security threats. Built with Python and PySide6, this tool provides a user-friendly interface to detect suspicious elements like embedded JavaScript, automatic actions, and external links — helping users make informed decisions before opening potentially malicious documents.

Created by **Erfan Nahidi**.

---


## Features

* **Detailed Threat Analysis:** Scans for suspicious keywords like `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile` using `pdfid.py`.
* **Intuitive GUI:** Modern, responsive interface built with PySide6.
* **Light & Dark Modes:** Toggle between themes for visual comfort.
* **Drag & Drop Support:** Quickly scan files by dragging them into the window.
* **Multi-Threaded Scanning:** Keeps the UI responsive during scans.
* **Threat Classification:** Categorizes threats as Safe, Low, Medium, High, or Critical.
* **Actionable Advice:** Offers practical suggestions based on scan results.
* **Cross-Platform:** Runs smoothly on Windows, macOS, and Linux.

---

## Download & Installation (For Users)

Download the latest version from the [GitHub Releases page](https://github.com/ErfanNahidi/pdf_scanner/releases):

* **Windows:** `.exe` installer
* **macOS:** `.dmg` file
* **Linux:** `.AppImage` or `.deb` package

---

## Setup & Installation (For Developers)

Follow these steps to run the app from source:

### 1. Clone the Repository

```bash
git clone https://github.com/ErfanNahidi/pdf_scanner.git
cd pdf_scanner
```

### 2. Install Dependencies

This project requires Python 3.9+ and PySide6. Use a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install PySide6
```

### 3. Set Up `pdfid.py`

Download `pdfid.py` from Didier Stevens' official tools:

* [Didier Stevens PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/)

Place `pdfid.py` in the project root (same folder as `gui.py` and `backend.py`).

---

## Usage

Run the application from the root directory:

```bash
python gui.py
```

* Drag and drop one or more PDF files into the window
* Or click **"Or Browse Files"** to select manually
* The scan starts automatically
* Click **"▼ Show Full Report"** on result cards to view keyword analysis and recommendations

---

## Project Structure

```
/
├── backend.py      # Core scanning engine and threat analysis logic
├── gui.py          # Main PySide6 GUI application
├── pdfid.py        # External PDF analysis tool (must be added manually)
└── README.md       # This file
```

---

## License

This project is licensed under the MIT L
