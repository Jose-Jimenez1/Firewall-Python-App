import json
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import threading

class BasicFirewall:
    def __init__(self):
        # Main firewall rules configuration
        self.rules = {
            "blocked_ips": [],
            "allowed_ips": [],  # Whitelist for always-allowed IPs
            "blocked_ports": [],
            "blocked_protocols": [],
            "mode": "allow_all",  # "allow_all" or "deny_all"
            "time_rules": []  # Time-based blocking rules
        }
        
        # Statistics tracking
        self.stats = {
            "packets_analyzed": 0,
            "packets_blocked": 0,
            "packets_allowed": 0
        }
        
        self.connection_tracker = {}  # Track connections per IP for rate limiting
        self.running = False
        self.load_rules()
    
    # ========== FILE MANAGEMENT (PROVIDED - Complex I/O operations) ==========
    
    def load_rules(self):
        # Load rules from JSON file if it exists
        if os.path.exists("firewall_rules.json"):
            with open("firewall_rules.json", "r") as f:
                self.rules = json.load(f)
            print("[+] Rules loaded from file")
        else:
            print("[!] No rules file found, using default configuration")
    
    def save_rules(self):
        # Save current rules to JSON file
        with open("firewall_rules.json", "w") as f:
            json.dump(self.rules, f, indent=4)
        print("[+] Rules saved")
    
    def export_rules(self, filename):
        # Export rules to share with team members
        with open(filename, "w") as f:
            json.dump(self.rules, f, indent=4)
        print(f"[+] Rules exported to {filename}")
    
    def import_rules(self, filename):
        # Import rules from external file
        try:
            with open(filename, "r") as f:
                self.rules = json.load(f)
            print(f"[+] Rules imported from {filename}")
        except FileNotFoundError:
            print(f"[!] File {filename} not found")
    
    def log_event(self, event):
        # Log blocked events to file with timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("firewall_log.txt", "a") as f:
            f.write(f"[{timestamp}] {event}\n")
    
    def send_alert(self, severity, message):
        # Send alerts for critical security events
        alert = f"[{severity}] {message}"
        print(f"\n🚨 ALERT: {alert}")
        
        with open("alerts.txt", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {alert}\n")
    
    # ========== UTILITY FUNCTIONS (PROVIDED - Complex lookups) ==========
    
    def identify_service(self, port):
        # Identify common services by port number
        common_ports = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return common_ports.get(port, f"Port-{port}")
    
    def list_interfaces(self):
        # Show available network interfaces (uses scapy)
        interfaces = get_if_list()
        print("\n=== Available Network Interfaces ===")
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")
        return interfaces
    
    def select_interface(self):
        # Let user choose which interface to monitor
        interfaces = self.list_interfaces()
        try:
            choice = int(input("\nSelect interface number (0 for all): ")) - 1
            if choice == -1:
                return None  # Monitor all interfaces
            return interfaces[choice]
        except (ValueError, IndexError):
            print("[!] Invalid selection, monitoring all interfaces")
            return None
    
    # ========== DETECTION FUNCTIONS (PROVIDED - Complex algorithms) ==========
    
    def check_rate_limit(self, ip):
        # Detect flooding attacks from same IP (anti-DDoS)
        current_time = datetime.now()
        
        if ip not in self.connection_tracker:
            self.connection_tracker[ip] = []
        
        # Remove old entries (older than 10 seconds)
        self.connection_tracker[ip] = [
            t for t in self.connection_tracker[ip] 
            if (current_time - t).seconds < 10
        ]
        
        # Add current connection
        self.connection_tracker[ip].append(current_time)
        
        # If more than 100 connections in 10 seconds, block
        if len(self.connection_tracker[ip]) > 100:
            self.add_blocked_ip(ip)
            self.send_alert("HIGH", f"Rate limit exceeded for {ip} - Auto-blocked")
            return True
        return False
    
    def is_blocked_by_time(self, ip):
        # Check if IP is blocked based on time-based rules
        current_time = datetime.now().strftime("%H:%M")
        for rule in self.rules["time_rules"]:
            if rule["ip"] == ip:
                if rule["start"] <= current_time <= rule["end"]:
                    return True
        return False
    
    # ========== PACKET ANALYSIS (PROVIDED - Core firewall logic) ==========
    
    def analyze_packet(self, packet):
        # Analyze each captured packet and decide whether to block it
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        
        # Update statistics
        self.stats["packets_analyzed"] += 1
        
        # Identify protocol and port
        protocol_name = "Unknown"
        dst_port = None
        
        if packet.haslayer(TCP):
            protocol_name = "TCP"
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
        
        # Initialize blocking variables
        blocked = False
        reason = ""
        
        # RULE 0: Check whitelist first (always allow)
        if src_ip in self.rules["allowed_ips"]:
            self.stats["packets_allowed"] += 1
            return
        
        # RULE 1: Check rate limiting
        if self.check_rate_limit(src_ip):
            blocked = True
            reason = f"Rate limit exceeded"
        
        # RULE 2: Check time-based rules
        if self.is_blocked_by_time(src_ip):
            blocked = True
            reason = f"Blocked by time-based rule"
        
        # RULE 3: Check blocked IPs
        if src_ip in self.rules["blocked_ips"]:
            blocked = True
            reason = f"Blocked source IP: {src_ip}"
        
        # RULE 4: Check blocked ports
        if dst_port and dst_port in self.rules["blocked_ports"]:
            blocked = True
            service = self.identify_service(dst_port)
            reason = f"Blocked destination port: {dst_port} ({service})"
        
        # RULE 5: Check blocked protocols
        if protocol_name in self.rules["blocked_protocols"]:
            blocked = True
            reason = f"Blocked protocol: {protocol_name}"
        
        # RULE 6: Check packet size (block unusually large packets)
        if packet_size > 10000:
            blocked = True
            reason = f"Packet too large: {packet_size} bytes"
        
        # Log and display results
        if blocked:
            self.stats["packets_blocked"] += 1
            service_info = f" ({self.identify_service(dst_port)})" if dst_port else ""
            event = f"BLOCKED - {reason} | {src_ip}:{dst_port if dst_port else 'N/A'}{service_info} -> {dst_ip} [{protocol_name}] Size: {packet_size}B"
            print(f"[BLOCKED] {event}")
            self.log_event(event)
        else:
            self.stats["packets_allowed"] += 1
    
    def start_monitoring(self, interface=None):
        # Start packet capture and monitoring (uses scapy for low-level packet capture)
        self.running = True
        print(f"\n[+] Firewall started - Monitoring network traffic...")
        print(f"[+] Mode: {self.rules['mode']}")
        print(f"[+] Blocked IPs: {len(self.rules['blocked_ips'])}")
        print(f"[+] Allowed IPs (Whitelist): {len(self.rules['allowed_ips'])}")
        print(f"[+] Blocked Ports: {self.rules['blocked_ports']}")
        print(f"[+] Blocked Protocols: {self.rules['blocked_protocols']}")
        print(f"[+] Interface: {interface if interface else 'All'}")
        print("[!] Press Ctrl+C to stop\n")
        
        try:
            # Capture packets - intercepts network traffic
            sniff(prn=self.analyze_packet, store=False, iface=interface)
        except KeyboardInterrupt:
            print("\n[!] Stopping firewall...")
            self.running = False
            self.show_statistics()
        except Exception as e:
            print(f"[!] Error: {e}")
            print("[!] Make sure you're running as Administrator")
    
    # ========== ADD RULES (TODO: Complete these - Pattern provided) ==========
    
    def add_blocked_ip(self, ip):
        # TODO: Add IP to blocklist
        # Check if IP is not already in blocked_ips list
        # If not present, add it and print success message
        # If already present, print "already in blocklist" message
        if ip not in self.rules["blocked_ips"]:
            self.rules["blocked_ips"].append(ip)
            print(f"[+] IP {ip} added to blocklist")
        else:
            print(f"[!] IP {ip} already in blocklist")
    
    def add_allowed_ip(self, ip):
        # TODO: Add IP to whitelist (same pattern as add_blocked_ip)
        # Use self.rules["allowed_ips"] instead
        pass
    
    def add_blocked_port(self, port):
        # TODO: Add port to blocklist (same pattern, use self.rules["blocked_ports"])
        # Also print the service name using self.identify_service(port)
        pass
    
    def add_blocked_protocol(self, protocol):
        # TODO: Add protocol to blocklist (same pattern, use self.rules["blocked_protocols"])
        pass
    
    def add_time_rule(self, ip, start_time, end_time):
        # TODO: Add time-based blocking rule
        # Create a dictionary with keys: "ip", "start", "end"
        # Append to self.rules["time_rules"]
        # Print confirmation message
        pass
    
    # ========== REMOVE RULES (TODO: Complete these - Similar pattern to ADD) ==========
    
    def remove_blocked_ip(self, ip):
        # TODO: Remove IP from blocklist
        # Check if IP is in the list, if yes remove it, if no print "not in blocklist"
        if ip in self.rules["blocked_ips"]:
            self.rules["blocked_ips"].remove(ip)
            print(f"[+] IP {ip} removed from blocklist")
        else:
            print(f"[!] IP {ip} not in blocklist")
    
    def remove_allowed_ip(self, ip):
        # TODO: Remove IP from whitelist (same pattern, use allowed_ips)
        pass
    
    def remove_blocked_port(self, port):
        # TODO: Remove port from blocklist (same pattern, use blocked_ports)
        pass
    
    def remove_blocked_protocol(self, protocol):
        # TODO: Remove protocol from blocklist (same pattern, use blocked_protocols)
        pass
    
    # ========== DISPLAY INFORMATION (TODO: Complete these) ==========
    
    def show_rules(self):
        # TODO: Display all current firewall rules in a formatted way
        # Print: mode, blocked_ips, allowed_ips, blocked_ports, blocked_protocols, time_rules
        # Use print statements with clear formatting
        print("\n" + "=" * 50)
        print("FIREWALL RULES")
        print("=" * 50)
        # TODO: Print all rules here
        print("=" * 50 + "\n")
    
    def show_statistics(self):
        # TODO: Display firewall statistics
        # Print: packets_analyzed, packets_blocked, packets_allowed
        # Calculate and print block_rate and allow_rate percentages
        # Formula: (blocked / analyzed) * 100
        print("\n" + "=" * 50)
        print("FIREWALL STATISTICS")
        print("=" * 50)
        # TODO: Print statistics here
        print("=" * 50 + "\n")
    
    def reset_statistics(self):
        # TODO: Reset all statistics to zero
        # Set packets_analyzed, packets_blocked, packets_allowed all to 0
        # Print confirmation message
        pass


def show_menu():
    # TODO: Display main menu with all 17 options
    # Number each option from 1-17
    # Format nicely with headers and separators
    print("\n" + "=" * 50)
    print("BASIC FIREWALL MENU")
    print("=" * 50)
    print("1.  Start Firewall")
    print("2.  Add Blocked IP")
    # TODO: Add options 3-17 here
    print("17. Exit")
    print("=" * 50)


def main():
    # Main program entry point
    print("=" * 50)
    print("COMPLETE BASIC NETWORK FIREWALL")
    print("Requires Administrator privileges!")
    print("=" * 50)
    
    firewall = BasicFirewall()
    
    while True:
        show_menu()
        choice = input("\nSelect option: ").strip()
        
        # TODO: Handle option 1 - Start Firewall (Example provided)
        if choice == "1":
            print("\n[!] Starting firewall monitoring...")
            print("[!] Note: Run as Administrator for full functionality")
            interface = firewall.select_interface()
            firewall.start_monitoring(interface)
        
        # TODO: Handle option 2 - Add Blocked IP (Example provided)
        elif choice == "2":
            ip = input("Enter IP to block (e.g., 192.168.1.100): ").strip()
            firewall.add_blocked_ip(ip)
        
        # TODO: Handle option 3 - Add Allowed IP (similar to option 2)
        elif choice == "3":
            # Get IP from user input
            # Call firewall.add_allowed_ip(ip)
            pass
        
        # TODO: Handle option 4 - Add Blocked Port (Example provided with error handling)
        elif choice == "4":
            try:
                port = int(input("Enter port to block (e.g., 80, 443, 22): ").strip())
                firewall.add_blocked_port(port)
            except ValueError:
                print("[!] Invalid port number")
        
        # TODO: Handle option 5 - Add Blocked Protocol
        elif choice == "5":
            # Get protocol from user (TCP/UDP/ICMP)
            # Convert to uppercase with .upper()
            # Call firewall.add_blocked_protocol()
            pass
        
        # TODO: Handle option 6 - Add Time-based Rule
        elif choice == "6":
            # Get IP, start_time, end_time from user
            # Call firewall.add_time_rule(ip, start, end)
            pass
        
        # TODO: Handle options 7-10 (Remove rules - similar to add)
        elif choice == "7":
            pass  # Remove blocked IP
        
        elif choice == "8":
            pass  # Remove allowed IP
        
        elif choice == "9":
            pass  # Remove blocked port
        
        elif choice == "10":
            pass  # Remove blocked protocol
        
        # TODO: Handle option 11 - Show Rules
        elif choice == "11":
            # Call firewall.show_rules()
            pass
        
        # TODO: Handle option 12 - Show Statistics
        elif choice == "12":
            # Call firewall.show_statistics()
            pass
        
        # TODO: Handle option 13 - Reset Statistics
        elif choice == "13":
            # Ask for confirmation first
            # If user confirms, call firewall.reset_statistics()
            pass
        
        # TODO: Handle option 14 - Save Rules
        elif choice == "14":
            # Call firewall.save_rules()
            pass
        
        # TODO: Handle option 15 - Export Rules
        elif choice == "15":
            # Get filename from user
            # Call firewall.export_rules(filename)
            pass
        
        # TODO: Handle option 16 - Import Rules
        elif choice == "16":
            # Get filename from user
            # Call firewall.import_rules(filename)
            pass
        
        # TODO: Handle option 17 - Exit
        elif choice == "17":
            print("[+] Exiting firewall...")
            break
        
        else:
            print("[!] Invalid option")


if __name__ == "__main__":
    main()
