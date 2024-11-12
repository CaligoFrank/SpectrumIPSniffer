import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import customtkinter
import threading
import nmap
import socket
import os
import platform
import subprocess
import json

# Set the appearance mode and color theme to dark
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

class NetworkScannerApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Device Scanner")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.resizable(False, False)

        # Dictionary to store notes, mapping device identifiers to notes
        self.notes_file = "device_notes.json"
        self.device_notes = self.load_notes()

        # Set up the GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Title label
        self.title_label = customtkinter.CTkLabel(self, text="Network Device Scanner", font=("Helvetica", 24, "bold"))
        self.title_label.pack(pady=20)

        # Scan button
        self.scan_button = customtkinter.CTkButton(self, text="Scan Network", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Progress label
        self.progress_label = customtkinter.CTkLabel(self, text="")
        self.progress_label.pack(pady=5)

        # Progress bar
        self.progress_bar = customtkinter.CTkProgressBar(self, width=600)
        self.progress_bar.pack(pady=5)
        self.progress_bar.set(0)

        # Treeview for displaying devices
        self.tree_frame = customtkinter.CTkFrame(self)
        self.tree_frame.pack(pady=10, fill="both", expand=True)

        self.device_tree = ttk.Treeview(self.tree_frame, show='headings', selectmode='browse')
        self.device_tree.pack(side="left", fill="both", expand=True)

        # Configure scrollbar
        self.tree_scroll = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.device_tree.yview)
        self.tree_scroll.pack(side="right", fill="y")
        self.device_tree.configure(yscrollcommand=self.tree_scroll.set)

        self.device_tree["columns"] = ("IP Address", "MAC Address", "Device Type", "Hostname", "Vendor", "Note")
        self.device_tree.column("IP Address", anchor=tk.W, width=120)
        self.device_tree.column("MAC Address", anchor=tk.W, width=150)
        self.device_tree.column("Device Type", anchor=tk.W, width=120)
        self.device_tree.column("Hostname", anchor=tk.W, width=150)
        self.device_tree.column("Vendor", anchor=tk.W, width=150)
        self.device_tree.column("Note", anchor=tk.W, width=150)

        self.device_tree.heading("IP Address", text="IP Address", anchor=tk.W)
        self.device_tree.heading("MAC Address", text="MAC Address", anchor=tk.W)
        self.device_tree.heading("Device Type", text="Device Type", anchor=tk.W)
        self.device_tree.heading("Hostname", text="Hostname", anchor=tk.W)
        self.device_tree.heading("Vendor", text="Vendor", anchor=tk.W)
        self.device_tree.heading("Note", text="Note", anchor=tk.W)

        # Style the treeview for dark theme
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#2E2E2E",
                        foreground="white",
                        rowheight=25,
                        fieldbackground="#2E2E2E")
        style.map('Treeview', background=[('selected', '#007ACC')], foreground=[('selected', 'white')])

        # Bind double-click event to show device details and add/edit note
        self.device_tree.bind("<Double-1>", self.show_device_details)

    def start_scan(self):
        # Disable the scan button to prevent multiple scans
        self.scan_button.configure(state="disabled")
        self.progress_label.configure(text="Scanning... Please wait.")
        self.progress_bar.set(0)

        # Start the scanning in a separate thread to avoid freezing the GUI
        scan_thread = threading.Thread(target=self.scan_network)
        scan_thread.start()

    def scan_network(self):
        # Get the local network IP range
        ip_range = self.get_network_ip_range()
        if not ip_range:
            self.update_progress("Could not determine local IP range.", reset_button=True)
            return

        # Create the nmap scanner object
        nm = nmap.PortScanner()

        try:
            # Perform the scan
            nm.scan(hosts=ip_range, arguments='-sn')

            # Clear the treeview
            self.clear_treeview()

            total_hosts = len(nm.all_hosts())
            processed_hosts = 0

            # Process scan results
            for host in nm.all_hosts():
                ip = host
                hostname = nm[host].hostname() if nm[host].hostname() else ''
                state = nm[host].state()

                mac = ''
                vendor = ''
                device_type = ''
                note = ''

                if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                    mac = nm[host]['addresses']['mac']
                    if 'vendor' in nm[host]:
                        vendor = nm[host]['vendor'].get(mac, '')

                # Attempt to guess the device type based on the vendor or hostname
                device_type = self.categorize_device(vendor, hostname)

                # Check if a note exists for this device
                device_id = mac if mac else ip
                note = self.device_notes.get(device_id, '')

                # Insert into treeview
                self.device_tree.insert('', 'end', values=(ip, mac, device_type, hostname, vendor, note))

                # Update progress
                processed_hosts += 1
                progress = processed_hosts / total_hosts
                self.progress_bar.set(progress)

            self.update_progress("Scan complete.", reset_button=True)
        except Exception as e:
            self.update_progress(f"An error occurred: {e}", reset_button=True)

    def get_network_ip_range(self):
        try:
            # Get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Calculate the IP range (assuming /24 subnet)
            ip_parts = local_ip.split('.')
            ip_range = '.'.join(ip_parts[:3]) + '.0/24'
            return ip_range
        except Exception as e:
            print(f"Error getting IP range: {e}")
            return None

    def categorize_device(self, vendor, hostname):
        # Simple categorization based on vendor or hostname keywords
        if vendor:
            vendor_lower = vendor.lower()
            if 'apple' in vendor_lower:
                return 'Apple Device'
            elif 'samsung' in vendor_lower:
                return 'Samsung Device'
            elif any(comp in vendor_lower for comp in ['intel', 'dell', 'hp', 'lenovo', 'asus', 'acer']):
                return 'Computer'
            elif any(net in vendor_lower for net in ['cisco', 'tp-link', 'netgear', 'd-link', 'ubiquiti']):
                return 'Network Device'
            elif any(tv in vendor_lower for tv in ['sony', 'lg', 'panasonic']):
                return 'Smart TV'
            elif 'amazon' in vendor_lower:
                return 'Amazon Device'
            elif 'google' in vendor_lower:
                return 'Google Device'
            else:
                return 'Unknown Device'
        elif hostname:
            hostname_lower = hostname.lower()
            if 'iphone' in hostname_lower or 'ipad' in hostname_lower or 'ipod' in hostname_lower:
                return 'Apple Device'
            elif 'android' in hostname_lower:
                return 'Android Device'
            elif 'printer' in hostname_lower:
                return 'Printer'
            else:
                return 'Unknown Device'
        else:
            return 'Unknown Device'

    def update_progress(self, message, reset_button=False):
        self.progress_label.configure(text=message)
        if reset_button:
            self.scan_button.configure(state="normal")

    def clear_treeview(self):
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

    def show_device_details(self, event):
        selected_item = self.device_tree.selection()
        if selected_item:
            item_values = self.device_tree.item(selected_item)['values']
            ip = item_values[0]
            mac = item_values[1]
            device_type = item_values[2]
            hostname = item_values[3]
            vendor = item_values[4]
            note = item_values[5]

            device_id = mac if mac else ip

            # Prompt user to add or edit note
            detail_message = f"IP Address: {ip}\nMAC Address: {mac}\nDevice Type: {device_type}\nHostname: {hostname}\nVendor: {vendor}\n\nNote: {note}"
            user_choice = messagebox.askyesno("Device Details", f"{detail_message}\n\nWould you like to add or edit a note for this device?")
            if user_choice:
                new_note = simpledialog.askstring("Add/Edit Note", "Enter note for this device:", initialvalue=note)
                if new_note is not None:
                    # Update the note in the dictionary
                    self.device_notes[device_id] = new_note

                    # Save notes to file
                    self.save_notes()

                    # Update the note in the treeview
                    self.device_tree.item(selected_item, values=(ip, mac, device_type, hostname, vendor, new_note))
            else:
                pass  # Do nothing

    def load_notes(self):
        if os.path.exists(self.notes_file):
            try:
                with open(self.notes_file, 'r') as f:
                    notes = json.load(f)
                    return notes
            except Exception as e:
                print(f"Error loading notes: {e}")
                return {}
        else:
            return {}

    def save_notes(self):
        try:
            with open(self.notes_file, 'w') as f:
                json.dump(self.device_notes, f)
        except Exception as e:
            print(f"Error saving notes: {e}")

    def on_closing(self):
        self.destroy()

if __name__ == "__main__":
    # Check if nmap is installed
    def is_nmap_installed():
        try:
            if platform.system() == "Windows":
                subprocess.check_output(["nmap", "--version"], shell=True)
            else:
                subprocess.check_output(["nmap", "--version"])
            return True
        except Exception:
            return False

    if not is_nmap_installed():
        print("Nmap is not installed. Please install nmap to use this program.")
    else:
        app = NetworkScannerApp()
        app.mainloop()
