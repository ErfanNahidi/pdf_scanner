# PDF Threat Scanner

## Overview

A modern PDF threat scanning tool with PySide6 GUI, advanced PDF analysis via `pdfid`, and robust threading for smooth performance.

## Project Structure

```plaintext
pdf_scanner/
├── backend.py
├── gui.py
├── __pycache__/
└── src/
    ├── main.py
    ├── pdfid/
    ├── pdftools/
    └── utils/
```



## Requirements

* Python 3.9+
* PyQt6
* `pdfid` tool (included in `src/pdfid/`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/ErfanNahidi/pdf_scanner.git
   cd pdf_scanner
   ```



2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```



3. Prepare the `pdfid` tool as per instructions in `src/pdfid/`.

## Usage

Run the application:

```bash
python gui.py
```



This launches the PyQt6 GUI for scanning PDFs.

## Features

* Multi-threaded scanning to prevent UI freezing.
* Threat level classification with actionable insights.
* Detailed PDF feature analysis using `pdfid`.
* Responsive and user-friendly interface.

## License

MIT License


