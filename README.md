# Enhanced-DNS-Sniffer-GUI
A real-time DNS sniffer with a responsive PyQt5 GUI that captures DNS packets using Scapy and displays detailed query data, network speed, and status monitoring. Built with multi-threading for smooth performance and interactive control features
Enhanced DNS Sniffer with PyQt5 GUI
A real-time DNS sniffer with an interactive PyQt5 GUI that captures and displays DNS packets, including detailed query information, network speed, and signal strength. Built with Scapy for packet analysis and psutil for network monitoring, this tool provides an intuitive way to monitor DNS traffic and network performance in real time.

Features
Live DNS Sniffing: Captures DNS packets in real-time, showing timestamps, source and destination IPs, and query names.

Interactive GUI: View DNS data in a dynamic table, with the ability to pause, resume, or clear the capture at any time.

Network Monitoring: Displays current network speed, packet loss, and signal strength (with placeholders for future enhancements).

Multi-threaded Sniffing: Utilizes QThread for smooth GUI performance during packet sniffing.

Detailed Table View: Shows essential DNS information like Source IP, Destination IP, Query Name, and Response IP.

Technologies Used
Python

PyQt5

Scapy (for packet sniffing)

psutil (for network monitoring)

Threading/QThread (for smooth real-time updates)

Installation
To run the project, clone the repository and install the required dependencies.

1. Clone the Repository
bash
Copy code
git clone https://github.com/your-username/Enhanced-DNS-Sniffer-GUI.git
cd Enhanced-DNS-Sniffer-GUI
2. Set Up a Virtual Environment (Optional but Recommended)
bash
Copy code
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
3. Install Dependencies
bash
Copy code
pip install -r requirements.txt
4. Run the Application
bash
Copy code
python main.py
Future Improvements
Packet Loss Detection: Real-time detection and display of packet loss percentage.

Signal Strength Monitoring: Add support for advanced signal strength analysis.

Export Data: Implement CSV export functionality for the captured DNS data.

Custom Filtering: Enable advanced filtering for specific DNS queries or IP addresses.

Demo

License
This project is open-source and available under the MIT License.
