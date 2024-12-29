import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from utils.validator import is_valid_target, is_valid_port_range
from utils.logger import log_scan
from utils.nmap_runner import NmapRunner
import threading
import subprocess

class NmapGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DSC-Nmap-GUI")
        self.root.geometry("800x600")
        
        self.nmap_runner = NmapRunner(self.update_result)
        self.stop_event = threading.Event()  # Event to stop the scan threads

        self.progress_value = tk.DoubleVar()  # Progress bar value
        self.status_message = tk.StringVar(value="Ready")  # Status bar message

        self.create_menu()
        self.create_widgets()

        # Intercept close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_menu(self):
        """Create the menu bar with file and help options."""
        menu_bar = tk.Menu(self.root)

        # File Menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Help Menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)

    def create_widgets(self):
        """Create all widgets and input fields."""
        self.create_target_input()
        self.create_scan_options()
        self.create_scan_buttons()
        self.create_result_display()
        self.create_progress_bar()
        self.create_status_bar()

    def create_target_input(self):
        """Create the target input fields for IP/domain and port range."""
        target_frame = tk.Frame(self.root)
        target_frame.pack(pady=10, fill="x", padx=10)

        tk.Label(target_frame, text="Target:").pack(side="left", padx=5)
        self.target_entry = tk.Entry(target_frame, width=50)
        self.target_entry.pack(side="left", padx=5)
        self.target_entry.bind("<FocusOut>", self.validate_target)

        self.target_feedback = tk.Label(target_frame, text="", fg="red")
        self.target_feedback.pack(side="left", padx=5)
        
        tk.Label(target_frame, text="Port, Ports or Range:").pack(side="left", padx=5)
        self.port_range_entry = tk.Entry(target_frame, width=15)
        self.port_range_entry.pack(side="left", padx=5)

    def validate_target(self, event):
        """Validate the target IP/domain when the input field loses focus."""
        target = self.target_entry.get()
        if not is_valid_target(target):  # Use the updated validation method
            self.target_feedback.config(text="Invalid target! Use format 192.168.1.1-20 or example.com")
        else:
            self.target_feedback.config(text="")

    def create_scan_options(self):
        """Create the scan type and advanced options input fields."""
        options_frame = tk.Frame(self.root)
        options_frame.pack(pady=10, fill="x", padx=10)

        # Scan Type Selection
        scan_type_frame = tk.LabelFrame(options_frame, text="Scan Type", padx=10, pady=10)
        scan_type_frame.pack(fill="x", padx=5, pady=5)

        self.scan_type = tk.StringVar()

        basic_scan_types = [
            "-sn","-sS", "-sT", "-sU", "-sN", "-sF", "-sX"
        ]
        advanced_scan_types = [
            "-sA", "-sW", "-sM", "-sC", "-sI", "-sR", "-sP"
        ]
        
        # Basic Scan Type Dropdown
        tk.Label(scan_type_frame, text="Select Basic Scan Type:").pack(side="left", padx=5)
        self.basic_scan_dropdown = ttk.Combobox(scan_type_frame, textvariable=self.scan_type, values=basic_scan_types, width=10)
        self.basic_scan_dropdown.pack(side="left", padx=5)

        # Advanced Scan Type Dropdown
        self.advanced_scan_type = tk.StringVar()
        tk.Label(scan_type_frame, text="Select Advanced Scan Type:").pack(side="left", padx=5)
        self.advanced_scan_dropdown = ttk.Combobox(scan_type_frame, textvariable=self.advanced_scan_type, values=advanced_scan_types, width=10)
        self.advanced_scan_dropdown.pack(side="left", padx=5)

        # Service Detection Options
        service_frame = tk.LabelFrame(options_frame, text="Service Detection", padx=10, pady=10)
        service_frame.pack(fill="x", padx=5, pady=5)

        self.os_detection = tk.BooleanVar()
        self.service_scan = tk.BooleanVar()

        tk.Checkbutton(service_frame, text="OS Detection", variable=self.os_detection).pack(side="left", padx=5)
        tk.Checkbutton(service_frame, text="Service Scan", variable=self.service_scan).pack(side="left", padx=5)

        # Advanced Options (Verbose, Aggressive Scan)
        advanced_options_frame = tk.LabelFrame(options_frame, text="Advanced Options", padx=10, pady=10)
        advanced_options_frame.pack(fill="x", padx=5, pady=5)

        self.verbose = tk.BooleanVar()
        self.aggressive_scan = tk.BooleanVar()  # Aggressive scan option
        self.script_engine = tk.StringVar()

        tk.Checkbutton(advanced_options_frame, text="Verbose Output", variable=self.verbose).pack(side="left", padx=5)
        tk.Checkbutton(advanced_options_frame, text="Aggressive Scan", variable=self.aggressive_scan).pack(side="left", padx=5)

        # Skip Host Discovery
        target_input_options_frame = tk.LabelFrame(options_frame, text="Skip Host Discovery", padx=10, pady=10)
        target_input_options_frame.pack(fill="x", padx=5, pady=5)

        self.no_ping_option = tk.BooleanVar()
        tk.Checkbutton(target_input_options_frame, text="No Ping", variable=self.no_ping_option).pack(side="left", padx=5)
        
    def create_scan_buttons(self):
        """Create the buttons for starting, stopping, and clearing scans."""
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10, fill="x", padx=10)

        self.scan_button = tk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side="left", padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        # Clear Results Button
        self.clear_button = tk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side="left", padx=5)

    def create_result_display(self):
        """Create the text boxes for displaying results and errors."""
        result_frame = tk.Frame(self.root)
        result_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # Display Scan Results
        self.result_text = tk.Text(result_frame, wrap=tk.WORD, state="disabled", height=20, width=40)
        self.result_text.pack(side="left", padx=5, pady=5, fill="both", expand=True)

        # Display Errors
        self.error_text = tk.Text(result_frame, wrap=tk.WORD, state="disabled", height=20, width=40)
        self.error_text.pack(side="left", padx=5, pady=5, fill="both", expand=True)

    def create_progress_bar(self):
        """Create the progress bar to show scan progress."""
        progress_frame = tk.Frame(self.root)
        progress_frame.pack(fill="x", padx=10, pady=5)

        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_value, maximum=100)
        self.progress_bar.pack(fill="x", expand=True)

    def create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        status_frame = tk.Frame(self.root)
        status_frame.pack(fill="x", side="bottom")

        self.status_label = tk.Label(status_frame, textvariable=self.status_message, anchor="w")
        self.status_label.pack(fill="x")

    def update_progress(self, value):
        """Update the progress bar value."""
        self.progress_value.set(value)

    def update_status(self, message):
        """Update the status bar message."""
        self.status_message.set(message)

    def start_scan(self):
        """Start the Nmap scan with the provided options."""
        target = self.target_entry.get()
        port_range = self.port_range_entry.get()

        # Collect scan options
        options = {
            "os_detection": self.os_detection.get(),
            "service_scan": self.service_scan.get(),
            "verbose": self.verbose.get(),
            "scan_type": self.scan_type.get() if self.scan_type.get() else self.advanced_scan_type.get(),
            "script": self.script_engine.get(),
            "aggressive_scan": self.aggressive_scan.get(),
            "no_ping": self.no_ping_option.get(),
        }

        if not is_valid_target(target):
            messagebox.showerror("Error", "Invalid target. Please enter a valid IP or domain.")
            return

        if port_range and not is_valid_port_range(port_range):
            messagebox.showerror("Error", "Invalid port range. Please enter a valid range (e.g., 20-80).")
            return

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_message.set("Scanning...")

        # Start a new thread to run the scan
        self.stop_event.clear()
        scan_thread = threading.Thread(target=self.run_nmap_scan, args=(target, port_range, options))
        scan_thread.daemon = True
        scan_thread.start()

    def run_nmap_scan(self, target, port_range, options):
        """Run the Nmap scan command."""
        try:
            nmap_command = self.nmap_runner.build_nmap_command(target, port_range, options)
            process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                if self.stop_event.is_set():
                    process.terminate()
                    self.update_status("Scan stopped.")
                    break
                self.update_result(line)
                self.update_progress(100)  # Update progress to 100% on completion
            process.wait()
            self.update_status("Scan Completed.")
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
        finally:
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def stop_scan(self):
        """Stop the current Nmap scan."""
        self.stop_event.set()
        self.update_status("Scan Stopped")
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def update_result(self, result_line):
        """Update the result text widget with scan output."""
        self.result_text.config(state="normal")
        self.result_text.insert(tk.END, result_line)
        self.result_text.config(state="disabled")

    def clear_results(self):
        """Clear all displayed results."""
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

        self.error_text.config(state="normal")
        self.error_text.delete("1.0", tk.END)
        self.error_text.config(state="disabled")

    def export_results(self):
        """Export the results to a text file."""
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "w") as file:
                file.write(self.result_text.get("1.0", tk.END))

    def show_about(self):
        """Show information about the application."""
        messagebox.showinfo("About", "DSC-Nmap-GUI\nCreated by DSC YU Team")

    def on_closing(self):
        """Handle the window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()

# Run the Nmap GUI
if __name__ == "__main__":
    app = NmapGUI()
    app.root.mainloop()
