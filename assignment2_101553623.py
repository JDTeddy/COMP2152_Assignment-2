"""
Author: <Jared-Ian Duldulao>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime


print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")


# Dictionary mapping common port numbers to their well-known service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}



class NetworkTool:
    def __init__(self, target):
        self.__target = target



# Q3: What is the benefit of using @property and @target.setter?

# @property and @target.setter control how the target value is used. 
# The getter lets you read the value safely. 
# @target.setter checks that the value is not empty before saving it. 
# This prevents bad data from being used.

    @property
    def target(self):
        return self.__target
 
    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value
 
    def __del__(self):
        print("NetworkTool instance destroyed")



# Q1: How does PortScanner reuse code from NetworkTool?

# PortScanner uses code from NetworkTool by inheriting from it.
# It calls the parent constructor to store the target and reuse validation.
# This avoids rewriting the same code. It also uses the parent destructor when the object is deleted.

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()
 
    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()
 
    def scan_port(self, port):



# Q4: What would happen without try-except here?

# Without try-except, errors would cause the program to stop or cause threads to break. 
# If a port fails to connect, the program could crash and some results would be missing. 
# Try-except keeps the scan running and safely handles errors.

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((self.target, port))
                status = "Open" if result == 0 else "Closed"
                service_name = common_ports.get(port, "Unknown")
                with self.lock:
                    self.scan_results.append((port, status, service_name))
            finally:
                sock.close()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
 
    def get_open_ports(self):



# Q2: Why do we use threading instead of scanning one port at a time?

# Threading lets the scanner check multiple ports simultaneously.
# Each port can take up to about 1 second to respond. Without threading, scanning would take much longer.
# With threading, the scan finishes much faster.

        return [result for result in self.scan_results if result[1] == "Open"]



    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()



def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            port, status, service = result
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")



def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        for row in rows:
            # row: (id, target, port, status, service, scan_date)
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    pass
    # TODO: Get user input with try-except (Step ix)
    # - Target IP (default "127.0.0.1" if empty)
    # - Start port (1-1024)
    # - End port (1-1024, >= start port)
    # - Catch ValueError: "Invalid input. Please enter a valid integer."
    # - Range check: "Port must be between 1 and 1024."

    target_ip = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target_ip == "":
        target_ip = "127.0.0.1"



    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter starting port (1-1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")



    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter ending port (1-1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")



    scanner = PortScanner(target_ip)
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)
 
    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target_ip} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")
 
    save_results(target_ip, scanner.scan_results)
 
    see_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if see_history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# Diagram: See diagram_studentID.png in the repository root

# A new feature could grab information from open ports. 
# After finding an open port, the scanner connects and reads a small response to identify the service. 
# This could be done using a new method and a simple conditional check after detecting an open port.