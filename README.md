# CyberOX - Digital Forensics Tool with AI Malware Detection

CyberOX is a command-line tool designed to assist in forensic investigations. It incorporates AI-based malware detection, network traffic capture, disk recovery, hardware data acquisition, and report generation. This tool is developed using Python, and aims to simplify the process of digital forensics with powerful features and AI-based insights.
![image](https://github.com/user-attachments/assets/61794729-1b9e-48fd-b9ae-e609a4e2fc4c)

## Features
- **Disk Recovery**: Recovers partition information using `pytsk3`.
- **Hardware Data Acquisition**: Captures data from hardware devices connected via serial port.
- **Network Traffic Acquisition**: Captures live network traffic using `Scapy`.
- **AI-Based Malware Detection**: Detects malware using a pre-trained AI model with file feature extraction.
- **Forensic Report Generation**: Generates PDF reports of all evidence collected, with summaries and analysis.

## Requirements

- Python 3.x
- Dependencies listed in `requirements.txt`

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/<your-username>/CyberOX.git
    cd CyberOX
    ```

2. **Install required Python packages**:
    Make sure you have `pip` installed, then run:
    ```bash
    pip install -r requirements.txt
    ```
## Usage

CyberOX offers several features for forensic analysis. Here are some basic usage examples:

### Show Help
```bash
python cybrox.py --help
