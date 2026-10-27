import customtkinter as ctk
import time

# Set up the overall theme
ctk.set_appearance_mode("System")  # Options: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")

class ThreatDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window configuration
        self.title("Home Network Threat Detector")
        self.geometry("900x600")
        self.minsize(800, 500)

        # Configure grid layout (2 columns: Sidebar and Main Content)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ----------------- SIDEBAR -----------------
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ NetGuard", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Sidebar navigation buttons
        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=lambda: self.select_frame("dashboard"))
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.btn_devices = ctk.CTkButton(self.sidebar_frame, text="Unknown Devices", command=lambda: self.select_frame("devices"))
        self.btn_devices.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_traffic = ctk.CTkButton(self.sidebar_frame, text="Traffic & Ports", command=lambda: self.select_frame("traffic"))
        self.btn_traffic.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.btn_dns = ctk.CTkButton(self.sidebar_frame, text="DNS Monitor", command=lambda: self.select_frame("dns"))
        self.btn_dns.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        # Appearance mode toggle at the bottom of sidebar
        self.appearance_menu = ctk.CTkOptionMenu(self.sidebar_frame, values=["System", "Dark", "Light"], command=self.change_appearance_mode)
        self.appearance_menu.grid(row=6, column=0, padx=20, pady=20, sticky="ew")

        # ----------------- MAIN CONTENT FRAMES -----------------
        self.frames = {}
        for F in (DashboardFrame, DevicesFrame, TrafficFrame, DnsFrame):
            frame_name = F.__name__.replace("Frame", "").lower()
            frame = F(parent=self)
            self.frames[frame_name] = frame
            frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        # Show default view
        self.select_frame("dashboard")

    def select_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()

    def change_appearance_mode(self, new_mode):
        ctk.set_appearance_mode(new_mode)


# ---------------------------------------------------------
# 1. Dashboard View
# ---------------------------------------------------------
class DashboardFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        title = ctk.CTkLabel(self, text="Security Overview", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(anchor="w", pady=(0, 20))

        # Status Banner
        self.status_box = ctk.CTkFrame(self, fg_color=("#95a5a6", "#7f8c8d"), corner_radius=10)
        self.status_box.pack(fill="x", pady=(0, 20))
        self.status_label = ctk.CTkLabel(self.status_box, text="Status: Backend Engine Not Connected [Coming Soon]", font=ctk.CTkFont(size=14, weight="bold"), text_color="white")
        self.status_label.pack(padx=20, pady=15)

        # Metric Cards Layout
        metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        metrics_frame.pack(fill="x", pady=10)
        metrics_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.create_card(metrics_frame, 0, "Connected Devices", "--")
        self.create_card(metrics_frame, 1, "Blocked Port Scans", "--")
        self.create_card(metrics_frame, 2, "DNS Queries Logged", "--")

        # Quick Live Logs Area
        log_label = ctk.CTkLabel(self, text="Real-Time Event Stream", font=ctk.CTkFont(size=16, weight="bold"))
        log_label.pack(anchor="w", pady=(20, 5))

        self.log_textbox = ctk.CTkTextbox(self, height=200)
        self.log_textbox.pack(fill="both", expand=True)
        self.log_textbox.insert("0.0", "[INFO] System initialized. Waiting for backend packet-capture implementation...\n")

        # Scan Control Button
        self.scan_btn = ctk.CTkButton(self, text="Run Full Security Scan (Coming Soon)", state="disabled")
        self.scan_btn.pack(anchor="e", pady=(15, 0))

    def create_card(self, parent, col, title, value):
        card = ctk.CTkFrame(parent, corner_radius=8)
        card.grid(row=0, column=col, padx=5, sticky="nsew")
        lbl_title = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12))
        lbl_title.pack(padx=15, pady=(10, 0))
        lbl_val = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=18, weight="bold"))
        lbl_val.pack(padx=15, pady=(0, 10))


# ---------------------------------------------------------
# 2. Unknown Device Detection View
# ---------------------------------------------------------
class DevicesFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        title = ctk.CTkLabel(self, text="Unknown Device Detection", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(anchor="w", pady=(0, 20))

        desc = ctk.CTkLabel(self, text="Displays all devices discovered on the subnet. [Coming Soon: Live ARP Scanning Integration]", font=ctk.CTkFont(size=13))
        desc.pack(anchor="w", pady=(0, 10))

        self.device_textbox = ctk.CTkTextbox(self, height=350)
        self.device_textbox.pack(fill="both", expand=True, pady=10)
        self.device_textbox.insert("0.0", "IP Address\t\tMAC Address\t\tVendor\t\tStatus\n" + "-"*75 + "\n")
        self.device_textbox.insert("end", "[Coming Soon] No live network interface bound. Scanning logic pending implementation.\n")

        btn_refresh = ctk.CTkButton(self, text="Scan Network for Devices (Coming Soon)", state="disabled")
        btn_refresh.pack(anchor="e", pady=10)


# ---------------------------------------------------------
# 3. Unauthorized Port Scanning & Traffic Detection View
# ---------------------------------------------------------
class TrafficFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        title = ctk.CTkLabel(self, text="Unauthorized Port Scanning & Unusual Traffic", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(anchor="w", pady=(0, 20))

        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True)

        tab_ports = self.tabs.add("Port Scanning Alerts")
        tab_traffic = self.tabs.add("Unusual Traffic Anomalies")

        self.port_log = ctk.CTkTextbox(tab_ports)
        self.port_log.pack(fill="both", expand=True)
        self.port_log.insert("0.0", "[INFO] Port monitoring integration pending implementation. [Coming Soon]\n")

        self.traffic_log = ctk.CTkTextbox(tab_traffic)
        self.traffic_log.pack(fill="both", expand=True)
        self.traffic_log.insert("0.0", "[INFO] Traffic anomaly detection integration pending implementation. [Coming Soon]\n")


# ---------------------------------------------------------
# 4. Monitor DNS View
# ---------------------------------------------------------
class DnsFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        title = ctk.CTkLabel(self, text="DNS Query Monitor", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(anchor="w", pady=(0, 20))

        desc = ctk.CTkLabel(self, text="Live tracker for local network DNS lookups. [Coming Soon: Raw Socket / Pcap Sniffer]", font=ctk.CTkFont(size=13))
        desc.pack(anchor="w", pady=(0, 10))

        self.dns_textbox = ctk.CTkTextbox(self, height=350)
        self.dns_textbox.pack(fill="both", expand=True, pady=10)
        self.dns_textbox.insert("0.0", "Timestamp\t\tSource IP\t\tRequested Domain\t\tStatus\n" + "-"*75 + "\n")
        self.dns_textbox.insert("end", "[Coming Soon] DNS sniffer engine not active.\n")

        btn_toggle = ctk.CTkButton(self, text="Toggle DNS Sniffer Engine (Coming Soon)", state="disabled", fg_color="#95a5a6")
        btn_toggle.pack(anchor="e", pady=10)


if __name__ == "__main__":
    app = ThreatDetectorApp()
    app.mainloop()
