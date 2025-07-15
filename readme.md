# PDF Threat Scanner

A modern, cross-platform desktop application designed to quickly analyze PDF files for potential security threats. Built with Python and PySide6, this tool provides a user-friendly interface to detect suspicious elements like embedded JavaScript, automatic actions, and external links, helping users make informed decisions before opening potentially malicious documents.

Created by **Erfan Nahidi**.


---

## Features

* **Detailed Threat Analysis:** Leverages the power of `pdfid.py` to scan for a wide range of potentially malicious keywords within a PDF's structure, including `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, and `/EmbeddedFile`.
* **Intuitive Graphical User Interface:** A clean, modern, and responsive UI built with PySide6 that makes scanning files effortless.
* **Light & Dark Modes:** Includes a stylish theme toggle to switch between light and dark modes for user comfort.
* **Drag & Drop Functionality:** Scan one or multiple PDF files easily by dragging them onto the application window.
* **Multi-Threaded Scanning:** The scanning process runs on a separate thread, ensuring the user interface remains responsive and never freezes.
* **Clear Threat Assessment:** Classifies threats into distinct levels (Safe, Low, Medium, High, Critical) with clear visual indicators.
* **Actionable Recommendations:** Provides straightforward security advice based on the detected threats.
* **Cross-Platform:** Designed to run on Windows, macOS, and Linux.

---

## Download & Installation (For Users)

You can download the latest installable version for your operating system from the **[GitHub Releases page](https://github.com/ErfanNahidi/pdf_scanner/releases)**.

* **Windows:** Download the `.exe` installer.
* **macOS:** Download the `.dmg` file.
* **Linux:** Download the `.AppImage` or `.deb` package.

---

## Setup & Installation (For Developers)

If you wish to run the application from the source code, follow these steps.

**1. Clone the Repository**

```bash
git clone [https://github.com/ErfanNahidi/pdf_scanner.git](https://github.com/ErfanNahidi/pdf_scanner.git)
cd pdf_scanner
2. Install DependenciesThis project requires Python 3.9+ and PySide6. It's highly recommended to use a virtual environment.# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

# Install the required packages
pip install PySide6
3. Set up pdfid.pyThis tool requires the pdfid.py script from Didier Stevens to function.Download pdfid.py from the official source: Didier Stevens' PDF ToolsPlace the downloaded pdfid.py file inside the project directory (the same folder as gui.py and backend.py). The application is designed to find it automatically when placed here.UsageOnce the setup is complete, run the application from the project's root directory:python gui.py
Drag and drop one or more PDF files onto the main window.Alternatively, click the "Or Browse Files" button to open a file dialog.The scan will begin automatically.Click "▼ Show Full Report" on any result card to see a detailed breakdown of all detected PDF keywords and security recommendations.Project Structure/
├── backend.py      # Core scanning engine and threat analysis logic.
├── gui.py          # Main application file with all PySide6 UI code.
├── pdfid.py        # (Must be added manually) External PDF analysis tool.
└── README.md       # This file.
