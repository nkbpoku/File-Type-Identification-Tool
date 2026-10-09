# File Type Identification Tool

A local Python desktop app that checks file contents to identify
supported formats and compares them with their filename extensions.

Renaming a file changes its name, not its contents. This tool helps
spot files whose extensions do not match their detected signatures.

## Features

- Choose a file or drag and drop it into the app.
- Click Identify to inspect the selected file.
- Detect PNG and PDF signatures.
- Recognise small UTF-8 text files as plain text candidates.
- Compare recognised signatures with filename extensions.
- Suggest an extension based on the findings.
- Display readable file sizes, locations and detection explanations.
- Clear the selection or return home using Done.
- Process files locally without uploading them.

## Built With

- Python
- Tkinter — desktop interface
- tkinterdnd2 — drag-and-drop support
- pathlib — file paths and metadata

## Setup

Install Python 3 with Tkinter support, then install the dependency:

```bash
python -m pip install tkinterdnd2