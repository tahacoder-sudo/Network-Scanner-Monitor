import sys
import time
import socket
import sqlite3
import platform
import subprocess
import csv
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt


# --- DATABASE MODULE ---
class NetworkDatabase:
    def __init__(self, db_path="network_history.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS service_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    port INTEGER,
                    status TEXT,
                    timestamp TEXT
                )
            """)
            conn.commit()

    def upsert_device(self, ip: str, hostname: str):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT first_seen FROM devices WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            if row:
                cursor.execute("""
                    UPDATE devices 
                    SET hostname = ?, last_seen = ?, status = 'ONLINE' 
                    WHERE ip = ?
                """, (hostname, now, ip))
            else:
                cursor.execute("""
                    INSERT INTO devices (ip, hostname, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, 'ONLINE')
                """, (ip, hostname, now, now))
            conn.commit()
        self.export_to_readable_files()

    def log_alert(self, ip: str, port: int, status: str):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO service_alerts (ip, port, status, timestamp)
                VALUES (?, ?, ?, ?)
            """, (ip, port, status, now))
            conn.commit()
        self.export_to_readable_files()

    def get_all_devices(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, hostname, first_seen, last_seen, status FROM devices")
            return cursor.fetchall()

    def export_to_readable_files(self):
        records = self.get_all_devices()

        # 1. Export as plain text file (.txt)
        with open("network_history.txt", "w", encoding="utf-8") as f:
            f.write("=========================================================================\n")
            f.write("                     NETWORK HISTORICAL DEVICE LOG                       \n")
            f.write("=========================================================================\n\n")
            f.write(f"{'IP ADDRESS':<18} | {'HOSTNAME':<25} | {'FIRST SEEN':<20} | {'LAST SEEN':<20} | {'STATUS':<8}\n")
            f.write("-" * 100 + "\n")
            for rec in records:
                f.write(f"{rec[0]:<18} | {rec[1]:<25} | {rec[2]:<20} | {rec[3]:<20} | {rec[4]:<8}\n")
            f.write("-" * 100 + "\n")

        # 2. Export as CSV (.csv)
        with open("network_history.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Hostname", "First Seen", "Last Seen", "Status"])
            writer.writerows(records)


# --- NOTIFIER MODULE ---
console = Console()


class SystemNotifier:
    @staticmethod
    def notify_service_down(ip: str, port: int):
        console.print(
            f"[bold red][CRITICAL][/bold red] Service on target [bold yellow]{ip}:{port}[/bold yellow] is UNREACHABLE!")

    @staticmethod
    def notify_service_up(ip: str, port: int):
        console.print(
            f"[bold green][RECOVERED][/bold green] Service on target [bold yellow]{ip}:{port}[/bold yellow] is ONLINE.")


# --- SCANNER MODULE ---
class NetworkScanner:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    @staticmethod
    def get_local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def ping_host(self, ip: str) -> bool:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = "1000" if platform.system().lower() == "windows" else "1"

        command = ["ping", param, "1", timeout_flag, timeout_val, ip]
        try:
            output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return output.returncode == 0
        except Exception:
            return False

    def resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown Device"

    def scan_ip(self, ip: str) -> Dict[str, str] | None:
        if self.ping_host(ip):
            hostname = self.resolve_hostname(ip)
            return {"ip": ip, "hostname": hostname}
        return None

    def sweep_subnet(self, subnet_prefix: str, max_threads: int = 50) -> List[Dict[str, str]]:
        target_ips = [f"{subnet_prefix}.{i}" for i in range(1, 255)]
        active_devices = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = executor.map(self.scan_ip, target_ips)

        for result in results:
            if result:
                active_devices.append(result)

        return active_devices

    def audit_port(self, ip: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except Exception:
            return False
        finally:
            sock.close()

    def audit_common_ports(self, ip: str, ports: List[int] = [21, 22, 80, 443, 8080, 3389]) -> List[int]:
        open_ports = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.audit_port, ip, port): port for port in ports}
            for future in future_to_port:
                port = future_to_port[future]
                if future.result():
                    open_ports.append(port)
        return sorted(open_ports)


# --- MAIN CLI APP ---
db = NetworkDatabase()
scanner = NetworkScanner()


def display_header():
    console.clear()
    console.print(
        Panel.fit(
            "[bold cyan]Smart Network Device Scanner & Monitor[/bold cyan]\n"
            "[dim]Computer Systems Engineering | Multi-Threaded Telemetry Tool[/dim]",
            border_style="cyan"
        )
    )


def run_subnet_scan():
    local_ip = scanner.get_local_ip()
    subnet_prefix = ".".join(local_ip.split(".")[:-1])

    console.print(f"\n[bold green][*][/bold green] Detected Local IP: [yellow]{local_ip}[/yellow]")
    console.print(
        f"[bold green][*][/bold green] Sweeping Subnet: [yellow]{subnet_prefix}.1 - {subnet_prefix}.254[/yellow] ...\n")

    start_time = time.time()
    devices = scanner.sweep_subnet(subnet_prefix)
    elapsed_time = round(time.time() - start_time, 2)

    table = Table(title=f"Active Network Hosts ({len(devices)} Found in {elapsed_time}s)")
    table.add_column("IP Address", style="cyan", justify="left")
    table.add_column("Hostname / Reverse DNS", style="magenta", justify="left")
    table.add_column("Status", style="green", justify="center")

    for dev in devices:
        ip = dev["ip"]
        hostname = dev["hostname"]
        db.upsert_device(ip, hostname)
        table.add_row(ip, hostname, "ONLINE")

    console.print(table)
    console.print(
        "\n[bold green][✔][/bold green] Database updated & readable log exported to [yellow]network_history.txt[/yellow]")


def run_port_audit():
    target_ip = Prompt.ask("\n[bold yellow]Enter target IP address for port audit[/bold yellow]")
    console.print(f"[bold green][*][/bold green] Auditing ports on [cyan]{target_ip}[/cyan] ...")

    ports_to_check = [21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080]
    open_ports = scanner.audit_common_ports(target_ip, ports_to_check)

    table = Table(title=f"Port Security Audit: {target_ip}")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("State", style="green", justify="center")
    table.add_column("Known Service", style="yellow", justify="left")

    service_names = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS",
                     3389: "RDP", 8080: "HTTP-Alt"}

    for port in ports_to_check:
        state = "OPEN" if port in open_ports else "CLOSED"
        style = "bold green" if state == "OPEN" else "dim red"
        table.add_row(str(port), f"[{style}]{state}[/{style}]", service_names.get(port, "Unknown"))

    console.print(table)


def run_service_monitor():
    target_ip = Prompt.ask("\n[bold yellow]Enter target IP to monitor[/bold yellow]")
    port = int(Prompt.ask("[bold yellow]Enter target Port (e.g. 80, 22, 443)[/bold yellow]", default="80"))
    interval = int(Prompt.ask("[bold yellow]Check interval in seconds[/bold yellow]", default="3"))
    duration = int(Prompt.ask("[bold yellow]Total monitoring time in seconds (e.g. 15)[/bold yellow]", default="15"))

    console.print(
        f"\n[bold green][*][/bold green] Monitoring [cyan]{target_ip}:{port}[/cyan] for {duration} seconds...\n")

    last_status = None
    start_time = time.time()
    check_num = 1

    try:
        while (time.time() - start_time) < duration:
            is_up = scanner.audit_port(target_ip, port)
            current_status = "UP" if is_up else "DOWN"

            if current_status != last_status:
                if is_up:
                    SystemNotifier.notify_service_up(target_ip, port)
                else:
                    SystemNotifier.notify_service_down(target_ip, port)
                db.log_alert(target_ip, port, current_status)
                last_status = current_status
            else:
                timestamp = time.strftime("%H:%M:%S")
                color = "green" if is_up else "red"
                console.print(
                    f"[{timestamp}] Heartbeat #{check_num}: [{color}]{target_ip}:{port} is {current_status}[/{color}]")

            check_num += 1
            time.sleep(interval)

        console.print("\n[bold green][✔][/bold green] Monitoring duration completed.")
    except (KeyboardInterrupt, SystemExit):
        console.print("\n[bold yellow][!][/bold yellow] Monitoring stopped manually.")


def view_db_records():
    db.export_to_readable_files()
    records = db.get_all_devices()
    table = Table(title="Historical Device Database")
    table.add_column("IP Address", style="cyan")
    table.add_column("Hostname", style="magenta")
    table.add_column("First Seen", style="yellow")
    table.add_column("Last Seen", style="blue")
    table.add_column("Last Status", style="green")

    for rec in records:
        table.add_row(rec[0], rec[1], rec[2], rec[3], rec[4])

    console.print(table)
    console.print(
        "\n[bold green][✔][/bold green] View raw records in [yellow]network_history.txt[/yellow] or [yellow]network_history.csv[/yellow]")


def main():
    while True:
        display_header()
        console.print("[1] Scan Local Subnet (Discover Devices)")
        console.print("[2] Audit Target IP Ports")
        console.print("[3] Live Service Uptime Monitor")
        console.print("[4] View Historical Device Log")
        console.print("[5] Export Readable Database Files (.txt & .csv)")
        console.print("[6] Exit")

        choice = Prompt.ask("\nSelect an option", choices=["1", "2", "3", "4", "5", "6"])

        if choice == "1":
            run_subnet_scan()
            input("\nPress Enter to return to menu...")
        elif choice == "2":
            run_port_audit()
            input("\nPress Enter to return to menu...")
        elif choice == "3":
            run_service_monitor()
            input("\nPress Enter to return to menu...")
        elif choice == "4":
            view_db_records()
            input("\nPress Enter to return to menu...")
        elif choice == "5":
            db.export_to_readable_files()
            console.print(
                "\n[bold green][SUCCESS][/bold green] Exported [yellow]network_history.txt[/yellow] and [yellow]network_history.csv[/yellow]!")
            input("\nPress Enter to return to menu...")
        elif choice == "6":
            console.print("[bold cyan]Exiting application...[/bold cyan]")
            sys.exit(0)


if __name__ == "__main__":
    main()













