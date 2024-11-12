# Network Device Scanner

## Overview
The **Network Device Scanner** is a Python application that provides a GUI for scanning and displaying network devices connected to the local network. It uses `nmap` to identify devices and displays essential information such as IP address, MAC address, device type, hostname, and vendor. Users can also add notes for each device, which are saved to a JSON file for future reference.

## Features
- Scans the local network to detect connected devices and gathers information about each device.
- Displays information such as IP, MAC, hostname, and vendor in a user-friendly GUI.
- Allows users to add notes for each device, with notes stored in a JSON file (`device_notes.json`).
- Dark theme for better user experience, using `customtkinter`.

## Prerequisites
- **Python 3.7 or higher**
- **nmap** installed on your system ([Download nmap](https://nmap.org/download.html)).
- **Dependencies**: See the `requirements.txt` file for Python library requirements.

To install the required Python libraries, use:
```bash
pip install -r requirements.txt
```


## Installation

### Clone the repository:
   
   git clone https://github.com/your-username/network-device-scanner.git 

### Navigate to the project directory:
    ```bash
    cd C://IpSniffer
    ```
### Install Dependencies:
    ```bash
    pip install -r requirements.txt
    ```
### Verify nmap installation:
#### Make sure nmap is correctly installed on your system by running:
    ```bash
    nmap --version
    ```
#### if nmap is not found, please install it from the official website.

# Usage

## Run the Application using Python:
    ```bash
    python IpSniffer.py
    ```
## OR Run using the .exe file
    ```bash
    D:\SpectrumIPSniffer\dist\IpSniffer.exe
    ```

### In the GUI click "Scan Network" to begin scanning the local network, Detected devices will appear in a list with details such as IP, MAC address, device type, hostname, and vendor.
### Double-click on a device entry to view details or add/edit notes.

# Project Structure

    ```bash
        network-device-scanner/
        ├── IpSniffer.py           # Main application file
        ├── requirements.txt       # List of dependencies
        ├── device_notes.json      # JSON file for storing device notes
        └── README.md              # Project documentation
    ```

# Troubleshooting
- if you recieve an error regarding missing Tcl or Tk Libraries, verify that Tcl/Tk libraries are correctly installed. You may need to reinstall Python and ensure Tcl/Tk is included.
- Ensure nmape is accessible in your systems PATH.

# Acknowledgments
- namp for network scanning capabilities.
- customtkinter for the GUI library that enables a customizable dark theme.


