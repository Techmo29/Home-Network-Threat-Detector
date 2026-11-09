import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
import time
import os

# Optional: Scapy for real packet sniffing (falls back to simulation if scapy is missing)
try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ThreatDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Home Network Threat Detector")
        self.geometry("850x520")
        self.minsize(700, 450)
        
        self.is_monitoring = False
        
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.create_widgets()

    def create_widgets(self):
        sidebar = ttk.Frame(self, width=200, relief="raised")
        sidebar.pack(side="left", fill="y")
        
        content_frame = ttk.Frame(self)
        content_frame.pack(side="right", expand=True, fill="both")
        
        self.frames = {}
        for F in (DashboardFrame, AlertsFrame, ConfigFrame):
            page_name = F.__name__
            frame = F(parent=content_frame, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
            
        content_frame.rowconfigure(0, weight=1)
        content_frame.columnconfigure(0, weight=1)
        
        ttk.Label(sidebar, text="Navigation", font=("Helvetica", 12, "bold")).pack(pady=20, padx=10)
        
        ttk.Button(sidebar, text="Dashboard", command=lambda: self.show_frame("DashboardFrame")).pack(fill="x", padx=10, pady=5)
        ttk.Button(sidebar, text="Alert Logs", command=lambda: self.show_frame("AlertsFrame")).pack(fill="x", padx=10, pady=5)
        ttk.Button(sidebar, text="Configuration", command=lambda: self.show_frame("ConfigFrame")).pack(fill="x", padx=10, pady=5)
        
        self.status_label = ttk.Label(sidebar, text="Status: Stopped", foreground="red")
        self.status_label.pack(side="bottom", pady=20)
        
        self.show_frame("DashboardFrame")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()
        # Refresh alert logs when switching to the Alerts frame
        if page_name == "AlertsFrame":
            frame.refresh_alerts()

    def toggle_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.status_label.config(text="Status: Running", foreground="green")
            threading.Thread(target=self.run_detector_loop, daemon=True).start()
        else:
            self.is_monitoring = False
            self.status_label.config(text="Status: Stopped", foreground="red")

    def load_config(self):
        if os.path.exists("config.json"):
            try:
                with open("config.json", "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"interface": "eth0", "threshold": "50"}

    def run_detector_loop(self):
        config = self.load_config()
        interface = config.get("interface", "eth0")
        threshold = int(config.get("threshold", 50))
        
        dashboard = self.frames["DashboardFrame"]
        dashboard.log_message(f"Starting threat detection on interface: {interface} (Threshold: {threshold} pkts/sec)")

        if SCAPY_AVAILABLE:
            packet_counts = {}

            def packet_callback(packet):
                if not self.is_monitoring:
                    return
                if IP in packet:
                    src_ip = packet[IP].src
                    current_sec = int(time.time())
                    key = (src_ip, current_sec)
                    packet_counts[key] = packet_counts.get(key, 0) + 1

                    if packet_counts[key] > threshold:
                        timestamp = time.strftime('%H:%M:%S')
                        desc = "High Packet Rate / Potential Port Scan"
                        dashboard.log_message(f"[{timestamp}] ALERT: High traffic from {src_ip}")
                        self.add_alert(timestamp, "HIGH", desc, src_ip)
                        # Reset count to prevent spamming alerts for the same second
                        packet_counts[key] = 0

            try:
                # Note: Sniffing requires proper permissions (e.g., Administrator on Windows or root on Linux/macOS)
                sniff(iface=interface if interface else None, prn=packet_callback, store=False, stop_filter=lambda x: not self.is_monitoring)
            except Exception as e:
                dashboard.log_message(f"[Error] Sniffing failed: {e}. Falling back to simulation mode.")
                self.run_simulation_loop(dashboard, threshold)
        else:
            dashboard.log_message("[Notice] Scapy not installed. Running in simulation mode.")
            self.run_simulation_loop(dashboard, threshold)

    def run_simulation_loop(self, dashboard, threshold):
        while self.is_monitoring:
            timestamp = time.strftime('%H:%M:%S')
            dashboard.log_message(f"[{timestamp}] Monitoring network packets (Simulation)...")
            time.sleep(3)

    def add_alert(self, timestamp, severity, description, source_ip):
        alerts_frame = self.frames["AlertsFrame"]
        alerts_frame.queue_alert(timestamp, severity, description, source_ip)


class DashboardFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        ttk.Label(self, text="Threat Detector Dashboard", font=("Helvetica", 16, "bold")).pack(pady=15)
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        
        self.toggle_btn = ttk.Button(btn_frame, text="Start Monitoring", command=self.on_toggle)
        self.toggle_btn.pack(side="left", padx=5)
        
        log_frame = ttk.LabelFrame(self, text="Live Activity & Alerts")
        log_frame.pack(expand=True, fill="both", padx=20, pady=10)
        
        self.log_text = tk.Text(log_frame, wrap="word", state="normal")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side="left", expand=True, fill="both")
        scrollbar.pack(side="right", fill="y")

    def on_toggle(self):
        self.controller.toggle_monitoring()
        if self.controller.is_monitoring:
            self.toggle_btn.config(text="Stop Monitoring")
        else:
            self.toggle_btn.config(text="Start Monitoring")

    def log_message(self, message):
        # Thread-safe insertion into the Text widget
        def append():
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)
        self.after(0, append)


class AlertsFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        ttk.Label(self, text="Alert History", font=("Helvetica", 16, "bold")).pack(pady=15)
        
        columns = ("Timestamp", "Severity", "Description", "Source IP")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
            
        self.tree.pack(expand=True, fill="both", padx=20, pady=10)
        
        # Buffer for alerts added from background threads
        self.pending_alerts = [("10:42:15", "HIGH", "Unauthorized Port Scan", "192.168.1.50")]
        self.refresh_alerts()

    def queue_alert(self, timestamp, severity, description, source_ip):
        def update():
            self.pending_alerts.insert(0, (timestamp, severity, description, source_ip))
            self.refresh_alerts()
        self.after(0, update)

    def refresh_alerts(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for alert in self.pending_alerts:
            self.tree.insert("", "end", values=alert)


class ConfigFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        ttk.Label(self, text="Configuration Settings", font=("Helvetica", 16, "bold")).pack(pady=15)
        
        form_frame = ttk.Frame(self)
        form_frame.pack(padx=20, pady=10, anchor="w")
        
        ttk.Label(form_frame, text="Network Interface:").grid(row=0, column=0, sticky="w", pady=5)
        self.interface_entry = ttk.Entry(form_frame, width=30)
        self.interface_entry.insert(0, "eth0")
        self.interface_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(form_frame, text="Scan Threshold (packets/sec):").grid(row=1, column=0, sticky="w", pady=5)
        self.threshold_entry = ttk.Entry(form_frame, width=30)
        self.threshold_entry.insert(0, "50")
        self.threshold_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Button(form_frame, text="Save Configuration", command=self.save_config).grid(row=2, column=1, sticky="e", pady=15)
        
        # Load existing config if available
        if os.path.exists("config.json"):
            try:
                with open("config.json", "r") as f:
                    data = json.load(f)
                    self.interface_entry.delete(0, tk.END)
                    self.interface_entry.insert(0, data.get("interface", "eth0"))
                    self.threshold_entry.delete(0, tk.END)
                    self.threshold_entry.insert(0, data.get("threshold", "50"))
            except Exception:
                pass

    def save_config(self):
        config_data = {
            "interface": self.interface_entry.get(),
            "threshold": self.threshold_entry.get()
        }
        try:
            with open("config.json", "w") as f:
                json.dump(config_data, f, indent=4)
            messagebox.showinfo("Success", "Configuration saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")


if __name__ == "__main__":
    app = ThreatDetectorApp()
    app.mainloop()
