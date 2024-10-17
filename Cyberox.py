import argparse
import os
import hashlib
import pefile  # PE file analysis (Windows)
import math
import joblib
import logging
from sklearn.ensemble import RandomForestClassifier
import scapy.all as scapy
import serial
import pytsk3
from fpdf import FPDF
import pyfiglet
from rich.console import Console
from rich.panel import Panel

# Setup logging
logging.basicConfig(filename='cybrox.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# ASCII banner for CyberOX
console = Console()
ascii_banner = pyfiglet.figlet_format("CYBER OX")
console.print(Panel.fit(f"[bold green]{ascii_banner}[/bold green]", subtitle="Project By Faizan-Ul-Hassan", subtitle_align="right"))

# -------------------------------
# CLI Help Section
# -------------------------------
def show_help():
    """Display help guide for CyberOX."""
    print("\nCyberOX Command Line Forensic Tool:")
    console.print("[bold yellow]FEATURES[/bold yellow]")
    
    options = [
        "1. EVIDENCE ACQUISITION",
        "2. AI-BASED MALWARE DETECTION",
        "3. REPORT GENERATION TO SUMMARIZE",
    ]
    
    for i, option in enumerate(options, 1):
        console.print(f"[green][{i}] {option}[/green]")
    
    console.print("\n[bold cyan]Usage examples:[/bold cyan]")
    console.print("[yellow]python cybrox.py acquire --source hard_drive --path /dev/sda[/yellow]")
    console.print("[yellow]python cybrox.py analyze --type malware --data ./sample_data/[/yellow]")
    console.print("[yellow]python cybrox.py report --evidence evidence.json --analysis analysis.json[/yellow]")

# -------------------------------
# 1. Disk Recovery (using pytsk3)
# -------------------------------
def list_disk_partitions():
    """List all disk partitions for recovery purposes."""
    try:
        img = pytsk3.Img_Info('/dev/sda')  # Assuming disk is mounted at /dev/sda
        partition_table = pytsk3.Volume_Info(img)
        partitions = [(partition.addr, partition.desc) for partition in partition_table]
        return partitions
    except Exception as e:
        logging.error(f"Error accessing disk: {str(e)}")
        return []

# -------------------------------
# 2. Hardware Data Acquisition (using pySerial)
# -------------------------------
def acquire_hardware_data(port='/dev/ttyUSB0', baudrate=9600):
    """Acquire data from hardware via serial port (e.g., sensors, devices)."""
    try:
        with serial.Serial(port, baudrate, timeout=1) as ser:
            ser.flush()
            data = []
            while True:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8').rstrip()
                    data.append(line)
                    print(f"Received from hardware: {line}")
                    if len(data) >= 10:  # Stop after receiving 10 lines
                        break
        return data
    except serial.SerialException as e:
        logging.error(f"Error accessing hardware: {str(e)}")
        return []

# -------------------------------
# 3. Network Acquisition (using scapy)
# -------------------------------
def capture_network_traffic(interface='eth0', packet_count=10):
    """Capture network traffic on the given interface."""
    try:
        packets = scapy.sniff(iface=interface, count=packet_count)
        traffic_data = [packet.summary() for packet in packets]
        for packet in traffic_data:
            print(packet)  # Print summary of each packet
        return traffic_data
    except Exception as e:
        logging.error(f"Error capturing network traffic: {str(e)}")
        return []

# -------------------------------
# 4. AI-Based Malware Detection (using a pre-trained model)
# -------------------------------
def calculate_entropy(data):
    """Calculate file entropy to detect packed files."""
    if len(data) == 0:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def extract_file_features(file_path):
    """Extract advanced file features for malware detection."""
    try:
        features = {}
        features['file_size'] = os.path.getsize(file_path)
        
        # Calculate file hashes
        with open(file_path, 'rb') as file:
            file_data = file.read()
            features['md5'] = hashlib.md5(file_data).hexdigest()
            features['sha1'] = hashlib.sha1(file_data).hexdigest()
            features['sha256'] = hashlib.sha256(file_data).hexdigest()
        
        # Entropy Calculation
        features['entropy'] = calculate_entropy(file_data)
        
        # PE file features (Windows executables only)
        try:
            pe = pefile.PE(file_path)
            features['imported_symbols'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        except pefile.PEFormatError:
            features['imported_symbols'] = 0  # Not a PE file or no imports

        return features
    except Exception as e:
        logging.error(f"Error extracting features from file {file_path}: {str(e)}")
        return None

def ai_malware_detection(directory, model_path='advanced_malware_model.pkl'):
    """Scan the directory for potential malware using AI-based detection."""
    try:
        model = joblib.load(model_path)  # Load the pre-trained model
    except Exception as e:
        logging.error(f"Error loading the model: {str(e)}")
        return []

    suspicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            features = extract_file_features(file_path)
            if features:
                try:
                    prediction = model.predict([list(features.values())])
                    if prediction == 1:  # 1 indicates malicious
                        suspicious_files.append(file_path)
                        print(f"Malicious file detected: {file_path}")
                except Exception as e:
                    logging.error(f"Error during prediction for {file_path}: {str(e)}")
    return suspicious_files

# -------------------------------
# 5. Report Generation (using FPDF)
# -------------------------------
class ForensicReport(FPDF):
    """PDF report generation for CyberOX forensic tool."""
    
    def header(self):
        """Report Header with Project and Author information."""
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, "CyberOX - Digital Forensics", 0, 1, 'C')
        self.cell(0, 10, "Project By Faizan-Ul-Hassan", 0, 1, 'C')
        self.ln(10)
    
    def chapter_title(self, title):
        """Add chapter title."""
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(4)
    
    def chapter_body(self, body):
        """Add chapter body."""
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()
    
    def add_chapter(self, title, body):
        self.add_page()
        self.chapter_title(title)
        self.chapter_body(body)

def generate_report(disk_data, hardware_data, network_data, malware_data):
    """Generate PDF report based on collected evidence and analysis results."""
    pdf = ForensicReport()
    
    # Add Disk Recovery section
    disk_info = "\n".join([f"Partition {p[0]}: {p[1]}" for p in disk_data])
    pdf.add_chapter("Disk Recovery", disk_info)
    
    # Add Hardware Acquisition section
    hardware_info = "\n".join(hardware_data)
    pdf.add_chapter("Hardware Acquisition", hardware_info)
    
    # Add Network Acquisition section
    network_info = "\n".join(network_data)
    pdf.add_chapter("Network Acquisition", network_info)
    
    # Add Malware Detection section
    malware_info = "\n".join(malware_data)
    pdf.add_chapter("AI-based Malware Detection", malware_info)
    
    # Save PDF
    try:
        pdf.output("cyberox_forensic_report.pdf")
        print("Report generated as cyberox_forensic_report.pdf")
    except Exception as e:
        logging.error(f"Error generating PDF report: {str(e)}")

# -------------------------------
# Automation: Main Function for CyberOX
# -------------------------------
def main():
    print("CyberOX - Digital Forensics Tool with AI Malware Detection")
    
    # Display Help Section
    show_help()

    # Step 1: Disk Recovery
    print("\n[1] Starting Disk Recovery...")
    disk_partitions = list_disk_partitions()
    
    # Step 2: Hardware Data Acquisition
    print("\n[2] Starting Hardware Data Acquisition...")
    hardware_data = acquire_hardware_data()
    
    # Step 3: Network Traffic Capture
    print("\n[3] Capturing Network Traffic...")
    network_data = capture_network_traffic()
    
    # Step 4: AI Malware Detection
    print("\n[4] Performing AI Malware Detection...")
    directory_to_scan = "."  # Change to the desired directory
    malware_data = ai_malware_detection(directory_to_scan)
    
    # Step 5: Generate Report
    print("\n[5] Generating Forensic Report...")
    generate_report(disk_partitions, hardware_data, network_data, malware_data)

if __name__ == "__main__":
    main()
