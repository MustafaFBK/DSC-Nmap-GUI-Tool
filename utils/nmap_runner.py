import subprocess
import threading
from datetime import datetime
import os


class NmapRunner:
    def __init__(self, update_result_callback):
        self.update_result_callback = update_result_callback
        self.scan_thread = None
        self.scan_process = None
        self.scan_stopped = False  # Flag to track if the scan is stopped

    def build_nmap_command(self, target, port_range, options):
        """Build the Nmap command based on user inputs."""
        base_command = ["nmap"]

        # Adding scan type
        if options.get("scan_type"):
            base_command.append(options["scan_type"])

        # Adding port range if provided
        if port_range:
            base_command.append(f"-p{port_range}")

        # Adding service detection
        if options.get("service_scan"):
            base_command.append("-sV")

        # Adding OS detection
        if options.get("os_detection"):
            base_command.append("-O")

        # Adding aggressive scan if selected
        if options.get("aggressive_scan"):
            base_command.append("-A")

        # Adding verbose output if selected
        if options.get("verbose"):
            base_command.append("-v")

        # Adding script engine if specified
        if options.get("script"):
            base_command.append(f"--script={options['script']}")

        # Additional options for target input
        if options.get("random_target"):
            base_command.append("--randomize-hosts")

        if options.get("no_ping"):
            base_command.append("-Pn")
            
        else:
            base_command.append(target)  # Target IP or domain

        return base_command

    def run_scan(self, command):
        """Execute the Nmap scan using the built command and stream results in real-time."""
        try:
            self.scan_process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for line in self.scan_process.stdout:
                if self.scan_process.poll() is not None or self.scan_stopped:
                    break  # Exit if the process is terminated
                self.update_result_callback(line.strip())
            self.scan_process.wait()
        except Exception as e:
            self.update_result_callback(f"Unexpected error: {str(e)}")
        finally:
            self.scan_process = None
            self.scan_stopped = False  # Reset the flag when the process ends

    def start_scan(self, target, port_range, options):
        """Start a new scan in a separate thread."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.update_result_callback("A scan is already running. Please wait.")
            return

        try:
            # Reset the scan stopped flag
            self.scan_stopped = False

            # Build the Nmap command
            command = self.build_nmap_command(target, port_range, options)
            self.scan_thread = threading.Thread(target=self.run_scan, args=(command,))
            self.scan_thread.start()
        except ValueError as e:
            self.update_result_callback(f"Error: {str(e)}")
        except Exception as e:
            self.update_result_callback(f"Unexpected error: {str(e)}")

    def stop_scan(self):
        """Stop the ongoing scan immediately."""
        if self.scan_process and self.scan_process.poll() is None and not self.scan_stopped:
            try:
                self.scan_stopped = True  # Set the flag to prevent redundant stop calls
                self.scan_process.kill()  # Forcefully kill the process
                self.update_result_callback("Scan terminated immediately.")
            except Exception as e:
                self.update_result_callback(f"Error stopping scan: {str(e)}")
        elif not self.scan_stopped:
            self.update_result_callback("No scan is currently running.")

    def log_scan(self, target, options, result):
        """Log scan results to a file for future reference."""
        log_filename = f"nmap_scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
        with open(log_filename, "w") as log_file:
            log_file.write(f"Scan started: {datetime.now()}\n")
            log_file.write(f"Target: {target}\n")
            log_file.write(f"Options: {options}\n")
            log_file.write("Scan Results:\n")
            log_file.write(result)

        return log_filename

