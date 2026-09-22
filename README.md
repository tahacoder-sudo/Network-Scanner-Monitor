Smart Network Device Scanner & Monitor
A simple Python command-line tool for discovering devices on the local network, checking common ports, monitoring service availability, and keeping historical network records.
Features
Scan the local subnet to discover active devices.
Resolve device hostnames.
Audit common network ports.
Monitor a specific IP and port for uptime changes.
Store device history using SQLite.
Export network history to .txt and .csv files.
Display results using Rich terminal tables and messages.
Requirements
Python 3.10+
rich library
Install the required library:
pip install rich
How to Run
python NetworkScanner.py
Use the menu to select:
Scan Local Subnet
Audit Target IP Ports
Live Service Uptime Monitor
View Historical Device Log
Export Database Files
Exit
Generated Files
The program creates:
network_history.db — SQLite database
network_history.txt — readable device history
network_history.csv — device history in CSV format
Note
Use the scanner only on networks and devices you are authorized to test.
