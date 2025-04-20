import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.scrollview import ScrollView
from kivy.graphics import Color, Rectangle
from kivy.clock import Clock
from kivy.uix.filechooser import FileChooserIconView
from datetime import datetime
import threading
import csv
from scapy.all import sniff, DNS, DNSQR, IP

# ----------------------------------------
# 🔹 DNS Table (Grid Layout with ScrollView)
# ----------------------------------------
class DNSLogTable(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', size_hint=(1, 0.8))
        self.log_data = []

        # Header Table
        header = GridLayout(cols=3, size_hint_y=None, height=40)
        header.add_widget(Label(text="Source IP", bold=True, color=(0, 0.5, 0.8, 1)))
        header.add_widget(Label(text="Queried Domain", bold=True, color=(0, 0.5, 0.8, 1)))
        header.add_widget(Label(text="Timestamp", bold=True, color=(0, 0.5, 0.8, 1)))
        self.add_widget(header)

        # Scrollable Log Entries
        self.scroll_view = ScrollView()
        self.log_grid = GridLayout(cols=3, size_hint_y=None)
        self.log_grid.bind(minimum_height=self.log_grid.setter('height'))
        self.scroll_view.add_widget(self.log_grid)
        self.add_widget(self.scroll_view)

    def add_entry(self, src_ip, query_name, timestamp):
        """Add new DNS log entry to the table."""
        self.log_grid.add_widget(Label(text=src_ip, color=(1, 1, 1, 1)))
        self.log_grid.add_widget(Label(text=query_name, color=(1, 1, 1, 1)))
        self.log_grid.add_widget(Label(text=timestamp, color=(1, 1, 1, 1)))
        self.log_data.append([src_ip, query_name, timestamp])

    def clear_entries(self):
        """Clear all log entries."""
        self.log_grid.clear_widgets()
        self.log_data = []

    def download_logs(self):
        """Download DNS logs as a CSV file."""
        with open('dns_logs.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Source IP", "Queried Domain", "Timestamp"])
            writer.writerows(self.log_data)

# ----------------------------------------
# 🔹 Main Application
# ----------------------------------------
class DNSSnifferApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical')
        with self.layout.canvas.before:
            Color(0.1, 0.1, 0.1, 1)
            self.rect = Rectangle(size=self.layout.size, pos=self.layout.pos)
            self.layout.bind(size=self._update_rect, pos=self._update_rect)

        # Button Layout (Centered at Top)
        self.control_panel = AnchorLayout(anchor_x='center', anchor_y='top', size_hint_y=0.15)
        self.button_layout = BoxLayout(size_hint=(None, None), size=(420, 50))
        self.start_button = Button(text="Start", size_hint=(None, None), size=(100, 40), background_color=(0, 0.8, 0, 1))
        self.stop_button = Button(text="Stop", size_hint=(None, None), size=(100, 40), background_color=(0.8, 0, 0, 1), disabled=True)
        self.clear_button = Button(text="Clear", size_hint=(None, None), size=(100, 40), background_color=(0.9, 0.5, 0, 1))
        self.download_button = Button(text="Download", size_hint=(None, None), size=(100, 40), background_color=(0.2, 0.6, 1, 1))
        self.start_button.bind(on_press=self.start_sniffing)
        self.stop_button.bind(on_press=self.stop_sniffing)
        self.clear_button.bind(on_press=self.clear_logs)
        self.download_button.bind(on_press=self.download_logs)

        self.button_layout.add_widget(self.start_button)
        self.button_layout.add_widget(self.stop_button)
        self.button_layout.add_widget(self.clear_button)
        self.button_layout.add_widget(self.download_button)
        self.control_panel.add_widget(self.button_layout)
        self.layout.add_widget(self.control_panel)

        # DNS Log Table (Expanded)
        self.log_table = DNSLogTable()
        self.layout.add_widget(self.log_table)

        # Status Label
        self.status_label = Label(text="DNS Sniffer - Ready", size_hint_y=0.1, color=(0.9, 0.9, 0.1, 1))
        self.layout.add_widget(self.status_label)

        self.sniffing_thread = None
        self.sniffing_active = False

        return self.layout

    def _update_rect(self, instance, value):
        self.rect.size = instance.size
        self.rect.pos = instance.pos

    # ----------------------------------------
    # 🔹 DNS Packet Processing
    # ----------------------------------------
    def process_packet(self, pkt):
        """Extract DNS query details and update the table."""
        if DNS in pkt and pkt[DNS].qr == 0:  # DNS Request
            src_ip = pkt[IP].src if IP in pkt else "N/A"
            query_name = pkt[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else "N/A"
            timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
            Clock.schedule_once(lambda dt: self.log_table.add_entry(src_ip, query_name, timestamp), 0)

    def sniff_packets(self):
        """Runs sniffing in a separate thread."""
        sniff(filter="udp port 53", prn=self.process_packet, store=0, stop_filter=lambda x: not self.sniffing_active)

    # ----------------------------------------
    # 🔹 Start/Stop Sniffing Functions
    # ----------------------------------------
    def start_sniffing(self, instance):
        """Start sniffing in a background thread."""
        self.status_label.text = "Sniffing Started..."
        self.start_button.disabled = True
        self.stop_button.disabled = False
        self.sniffing_active = True

        self.sniffing_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffing_thread.start()

    def stop_sniffing(self, instance):
        """Stop sniffing packets."""
        self.status_label.text = "Sniffing Stopped."
        self.start_button.disabled = False
        self.stop_button.disabled = True
        self.sniffing_active = False

    def clear_logs(self, instance):
        """Clear DNS logs."""
        self.log_table.clear_entries()
        self.status_label.text = "Logs Cleared."

    def download_logs(self, instance):
        """Download DNS logs to a CSV file."""
        self.log_table.download_logs()
        self.status_label.text = "Logs Downloaded."

if __name__ == "__main__":
    DNSSnifferApp().run()
