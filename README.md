# CyberOX - Digital Forensics Tool with AI Malware Detection

CyberOX is a command-line tool designed to assist in forensic investigations. It incorporates AI-based malware detection, network traffic capture, disk recovery, hardware data acquisition, and report generation. This tool is developed using Python, and aims to simplify the process of digital forensics with powerful features and AI-based insights.
![image](https://github.com/user-attachments/assets/61794729-1b9e-48fd-b9ae-e609a4e2fc4c)

Certainly! Setting up a Python virtual environment is an essential step to ensure that your project's dependencies are isolated from other Python packages on your system. Below, I've provided detailed instructions on how to create a Python virtual environment, updated the README to include these steps, and added a `.gitignore` file to prevent the virtual environment from being committed to your repository.

--
## Features
- **Disk Recovery**: Recover partition information using `pytsk3`.
- **Hardware Data Acquisition**: Capture data from hardware devices connected via serial port.
- **Network Traffic Acquisition**: Capture live network traffic using `Scapy`.
- **AI-Based Malware Detection**: Detect malware using a pre-trained AI model with file feature extraction.
- **Forensic Report Generation**: Generate PDF reports of all evidence collected, with summaries and analysis.

## Requirements

- Python 3.x
- Dependencies listed in `requirements.txt`

## Installation

1. **Clone the repository**:
    ```bash
  https://github.com/Def-Warrior/Cyber-OX/
    cd CyberOX
    ```

2. **Create a virtual environment**:
    ```bash
    python3 -m venv venv
    ```
    On Windows:
    ```bash
    python -m venv venv
    ```

3. **Activate the virtual environment**:
    - On **Linux/macOS**:
        ```bash
        source venv/bin/activate
        ```
    - On **Windows**:
        ```bash
        venv\Scripts\activate
        ```

4. **Install required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```

5. **Download the pre-trained AI model**:
    - **Model File**: `advanced_malware_model.pkl` (Place this file in the project root directory.)
    - **Note**: The model is required for AI-based malware detection.

## Usage

CyberOX offers several features for forensic analysis. Here are some basic usage examples:

### Show Help
```bash
python cybrox.py --help
```

### Disk Recovery
```bash
python cybrox.py acquire --source hard_drive --path /dev/sda
```

### AI-Based Malware Detection
```bash
python cybrox.py analyze --type malware --data ./sample_data/
```

### Report Generation
```bash
python cybrox.py report --evidence evidence.json --analysis analysis.json
```

## File Structure
- `cybrox.py`: Main entry point of the tool.
- `requirements.txt`: Lists all the dependencies.
- `cybrox.log`: Log file where all errors and processing information are saved.
- `advanced_malware_model.pkl`: Pre-trained AI model for malware detection.
- `cyberox_forensic_report.pdf`: Generated forensic report (after running the tool).
- `venv/`: Virtual environment directory (not included in version control; see `.gitignore`).

## Dependencies

This project uses the following Python libraries:
- `argparse`: Command-line argument parsing.
- `os`: File and directory handling.
- `hashlib`: For file hash generation.
- `pefile`: PE (Portable Executable) file analysis.
- `joblib`: Model saving/loading for the AI.
- `scapy`: Network traffic capture.
- `pyserial`: Hardware data acquisition.
- `pytsk3`: Disk partition recovery.
- `fpdf`: PDF report generation.
- `pyfiglet`: ASCII banner creation.
- `rich`: Beautiful CLI formatting and printing.

## Logging

The tool logs all activities and errors to a log file (`cybrox.log`). This can help with debugging and tracking forensic activities.

## Virtual Environment

Using a virtual environment is recommended to manage dependencies and avoid conflicts with other Python packages on your system.

### Creating a Virtual Environment

1. **Create the virtual environment**:
    ```bash
    python3 -m venv venv
    ```

2. **Activate the virtual environment**:
    - On **Linux/macOS**:
        ```bash
        source venv/bin/activate
        ```
    - On **Windows**:
        ```bash
        venv\Scripts\activate
        ```

3. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Deactivate when done**:
    ```bash
    deactivate
    ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contribution

Feel free to submit issues or contribute by creating pull requests.

## Author

- **Faizan-Ul-Hassan** - Developer and maintainer of CyberOX.

```

---

## .gitignore

To prevent the virtual environment and other unnecessary files from being tracked by Git, add a `.gitignore` file to your repository with the following content:

```gitignore
# Ignore virtual environment directory
venv/

# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
#  Usually these files are written by a python script from a template
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
pytest_cache/
nosetests.xml
coverage.xml
*.cover
.hypothesis/

# Translations
*.mo
*.pot

# Logs and databases
*.log
*.sql
*.sqlite

# OS-specific files
.DS_Store
Thumbs.db

# Reports
*.pdf

# Model files (if large and not stored in Git LFS)
*.pkl

# Environment variables
.env
```

---

## Additional Recommendations

- **Automate Environment Setup**:
  - Create a `setup.sh` script to automate the virtual environment creation and package installation.
  - **setup.sh**:
    ```bash
    #!/bin/bash

    # Create virtual environment
    python3 -m venv venv

    # Activate virtual environment
    source venv/bin/activate

    # Install dependencies
    pip install -r requirements.txt

    echo "Virtual environment setup complete."
    ```

  - Make the script executable:
    ```bash
    chmod +x setup.sh
    ```

- **Specify Python Version**:
  - If your project requires a specific Python version, mention it in the `README.md`.
  - Consider using tools like `pyenv` to manage Python versions.

- **Use Dependency Management Tools**:
  - **Pipenv**:
    - Install Pipenv:
      ```bash
      pip install pipenv
      ```
    - Install dependencies:
      ```bash
      pipenv install -r requirements.txt
      ```
    - Activate the virtual environment:
      ```bash
      pipenv shell
      ```
  - **Poetry**:
    - Install Poetry:
      ```bash
      pip install poetry
      ```
    - Initialize Poetry in your project:
      ```bash
      poetry init
      ```
    - Install dependencies:
      ```bash
      poetry install
      ```
    - Activate the virtual environment:
      ```bash
      poetry shell
      ```

---

## Updated Requirements File

Ensure your `requirements.txt` file lists all the necessary packages:

```plaintext
argparse
os-sys
hashlib
pefile
joblib
scapy
pyserial
pytsk3
fpdf
pyfiglet
rich
```

---

## Next Steps

1. **Add the `README.md` and `.gitignore` files** to your repository.

2. **Ensure that `venv/` is not tracked** by Git:
    - Check the status of your repository:
      ```bash
      git status
      ```
    - If `venv/` is listed, you may need to remove it from tracking:
      ```bash
      git rm -r --cached venv/
      ```

3. **Commit your changes**:
    ```bash
    git add .
    git commit -m "Add virtual environment setup and update README"
    git push origin main
    ```

4. **Provide Instructions for the Pre-trained AI Model**:
    - Since `advanced_malware_model.pkl` is required but not included in the repository (due to size or licensing), provide clear instructions on how to obtain it.

---

Feel free to reach out if you need further assistance or have any questions!
