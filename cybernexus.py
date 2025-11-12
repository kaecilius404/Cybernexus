#!/usr/bin/env python3
"""
CYBER-NEXUS GODMODE - FULLY WORKING ULTIMATE TOOLKIT
Created by KAECILIUS404
"""

import socket
import threading
import subprocess
import hashlib
import base64
import os
import time
from datetime import datetime
import json
import sys
import random
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class CyberNexusGodMode:
    def __init__(self):
        self.target = ""
        self.results = []
        self.session_id = self.generate_session_id()
        self.initialize_toolkit()
        self.show_banner()
        self.main_menu()

    def generate_session_id(self):
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def show_banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        
        banner = f"""
{Colors.RED}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║    ██████  ██    ██ ██████  ███████ ██████  ██    ██         ║
    ║   ██    ██ ██    ██ ██   ██ ██      ██   ██  ██  ██          ║
    ║   ██    ██ ██    ██ ██████  █████   ██████    ████           ║
    ║   ██    ██ ██    ██ ██   ██ ██      ██   ██    ██            ║
    ║    ██████   ██████  ██████  ███████ ██   ██    ██            ║
    ║                                                              ║
    ║    ██████   ██████  ██████  ██████  ███████ ███████ ███████  ║
    ║   ██    ██ ██    ██ ██   ██ ██   ██ ██      ██      ██       ║
    ║   ██    ██ ██    ██ ██   ██ ██████  █████   ███████ ███████  ║
    ║   ██    ██ ██    ██ ██   ██ ██   ██ ██           ██      ██  ║
    ║    ██████   ██████  ██████  ██████  ███████ ███████ ███████  ║
    ║                                                              ║
    ║                  [ G O D M O D E  A C T I V A T E D ]        ║
    ║                     Created by KAECILIUS404                 ║
    ║                   Session ID: {self.session_id}               ║
    ╚══════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
        print(f"{Colors.CYAN}[*] Initializing Cyber-Nexus GodMode System...{Colors.END}\n")

    def initialize_toolkit(self):
        dirs = ['scans', 'logs', 'reports', 'captures', 'output']
        for dir_name in dirs:
            os.makedirs(dir_name, exist_ok=True)

    def log_activity(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        with open(f"logs/cybernexus_{self.session_id}.log", "a") as log_file:
            log_file.write(log_entry + "\n")
        
        color = Colors.GREEN if level == "INFO" else Colors.RED if level == "ERROR" else Colors.YELLOW
        print(f"{color}[{level}] {message}{Colors.END}")

    def print_menu_header(self, title):
        print(f"\n{Colors.PURPLE}{Colors.BOLD}╔{'═' * 60}╗{Colors.END}")
        print(f"{Colors.PURPLE}{Colors.BOLD}║ {title.center(58)} ║{Colors.END}")
        print(f"{Colors.PURPLE}{Colors.BOLD}╚{'═' * 60}╝{Colors.END}")

    def main_menu(self):
        while True:
            self.print_menu_header("CYBER-NEXUS GODMODE MAIN MENU")
            
            menu_options = [
                f"{Colors.CYAN}1{Colors.END}. {Colors.GREEN}TARGET ACQUISITION{Colors.END}",
                f"{Colors.CYAN}2{Colors.END}. {Colors.YELLOW}NETWORK SCANNER{Colors.END}",
                f"{Colors.CYAN}3{Colors.END}. {Colors.RED}VULNERABILITY SCANNER{Colors.END}",
                f"{Colors.CYAN}4{Colors.END}. {Colors.PURPLE}WEB SECURITY AUDIT{Colors.END}",
                f"{Colors.CYAN}5{Colors.END}. {Colors.BLUE}PASSWORD TOOLS{Colors.END}",
                f"{Colors.CYAN}6{Colors.END}. {Colors.GREEN}SYSTEM INFORMATION{Colors.END}",
                f"{Colors.CYAN}7{Colors.END}. {Colors.YELLOW}GODMODE FULL SCAN{Colors.END}",
                f"{Colors.CYAN}0{Colors.END}. {Colors.RED}EXIT{Colors.END}"
            ]
            
            for option in menu_options:
                print(f"{Colors.PURPLE}║ {option:<56} ║{Colors.END}")
            print(f"{Colors.PURPLE}╚{'═' * 60}╝{Colors.END}")
            
            choice = input(f"\n{Colors.CYAN}[?] SELECT OPERATION {Colors.YELLOW}>>{Colors.END} ").strip()
            
            if choice == '1':
                self.target_acquisition()
            elif choice == '2':
                self.network_scanner_menu()
            elif choice == '3':
                self.vulnerability_scanner()
            elif choice == '4':
                self.web_security_audit()
            elif choice == '5':
                self.password_tools_menu()
            elif choice == '6':
                self.system_information()
            elif choice == '7':
                self.godmode_full_scan()
            elif choice == '0':
                self.exit_toolkit()
            else:
                print(f"{Colors.RED}[!] Invalid selection!{Colors.END}")

    def target_acquisition(self):
        self.print_menu_header("TARGET ACQUISITION")
        print(f"{Colors.PURPLE}║ {Colors.CYAN}Current Target: {Colors.YELLOW}{self.target if self.target else 'NOT SET'}{Colors.END}")
        print(f"{Colors.PURPLE}╚{'═' * 60}╝{Colors.END}")
        
        target = input(f"\n{Colors.CYAN}[?] ENTER TARGET (IP/Domain) {Colors.YELLOW}>>{Colors.END} ").strip()
        if target:
            self.target = target
            self.log_activity(f"Target acquired: {target}", "SUCCESS")

    # NETWORK SCANNER MODULE - FULLY WORKING
    def network_scanner_menu(self):
        while True:
            self.print_menu_header("NETWORK SCANNER")
            
            options = [
                f"{Colors.CYAN}1{Colors.END}. Fast Port Scanner",
                f"{Colors.CYAN}2{Colors.END}. Comprehensive Port Scan", 
                f"{Colors.CYAN}3{Colors.END}. Service Detection",
                f"{Colors.CYAN}4{Colors.END}. Ping Sweep",
                f"{Colors.CYAN}0{Colors.END}. Back to Main Menu"
            ]
            
            for option in options:
                print(f"{Colors.PURPLE}║ {option:<56} ║{Colors.END}")
            print(f"{Colors.PURPLE}╚{'═' * 60}╝{Colors.END}")
            
            choice = input(f"\n{Colors.CYAN}[?] SELECT SCAN TYPE {Colors.YELLOW}>>{Colors.END} ").strip()
            
            if choice == '1':
                self.fast_port_scanner()
            elif choice == '2':
                self.comprehensive_port_scan()
            elif choice == '3':
                self.service_detection()
            elif choice == '4':
                self.ping_sweep()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}[!] Invalid choice!{Colors.END}")

    def fast_port_scanner(self):
        if not self.target:
            print(f"{Colors.RED}[!] No target set!{Colors.END}")
            return
            
        print(f"{Colors.CYAN}[*] Scanning {self.target} for common ports...{Colors.END}")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    print(f"{Colors.GREEN}[+] Port {port}/tcp open - {service}{Colors.END}")
            except:
                pass

        print(f"{Colors.YELLOW}[*] Starting scan...{Colors.END}")
        start_time = time.time()
        
        threads = []
        for port in common_ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join()
            
        end_time = time.time()
        print(f"{Colors.CYAN}[*] Scan completed in {end_time - start_time:.2f} seconds{Colors.END}")
        print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports{Colors.END}")

    def comprehensive_port_scan(self):
        if not self.target:
            print(f"{Colors.RED}[!] No target set!{Colors.END}")
            return
            
        print(f"{Colors.CYAN}[*] Comprehensive scan on {self.target}...{Colors.END}")
        
        # Scan first 1000 ports
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    if port in [21, 22, 23, 25, 53, 80, 110, 443, 3389]:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        print(f"{Colors.GREEN}[+] Port {port}/tcp open - {service}{Colors.END}")
            except:
                pass

        print(f"{Colors.YELLOW}[*] Scanning first 1000 ports...{Colors.END}")
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, range(1, 1001))
            
        end_time = time.time()
        print(f"{Colors.CYAN}[*] Scan completed in {end_time - start_time:.2f} seconds{Colors.END}")
        print(f"{Colors.GREEN}[+] Total open ports found: {len(open_ports)}{Colors.END}")

    def service_detection(self):
        if not self.target:
            print(f"{Colors.RED}[!] No target set!{Colors.END}")
            return
            
        print(f"{Colors.CYAN}[*] Detecting services on {self.target}...{Colors.END}")
        
        services_to_check = [
            (21, "FTP"),
            (22, "SSH"), 
            (23, "Telnet"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (110, "POP3"),
            (443, "HTTPS"),
            (3389, "RDP")
        ]
        
        for port, service_name in services_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    print(f"{Colors.GREEN}[+] {service_name} service running on port {port}{Colors.END}")
                else:
                    print(f"{Colors.RED}[-] {service_name} not detected on port {port}{Colors.END}")
            except:
                print(f"{Colors.RED}[-] Error checking {service_name} on port {port}{Colors.END}")

    def ping_sweep(self):
        network = input(f"{Colors.CYAN}[?] Enter network (e.g., 192.168.1.0/24) {Colors.YELLOW}>>{Colors.END} ").strip()
        if not network:
            return
            
        print(f"{Colors.CYAN}[*] Starting ping sweep on {network}...{Colors.END}")
        
        base_ip = '.'.join(network.split('.')[:3])
        
        def ping_host(ip):
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    print(f"{Colors.GREEN}[+] Host alive: {ip}{Colors.END}")
                    return ip
            except:
                pass
            return None

        alive_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(ping_host, [f"{base_ip}.{i}" for i in range(1, 255)])
            alive_hosts = [ip for ip in results if ip]
            
        print(f"{Colors.CYAN}[*] Ping sweep completed. Found {len(alive_hosts)} alive hosts.{Colors.END}")

    # VULNERABILITY SCANNER - FULLY WORKING
    def vulnerability_scanner(self):
        if not self.target:
            print(f"{Colors.RED}[!] No target set!{Colors.END}")
            return
            
        self.print_menu_header("VULNERABILITY SCANNER")
        print(f"{Colors.CYAN}[*] Scanning {self.target} for common vulnerabilities...{Colors.END}")
        
        vulnerabilities = []
        
        # Check for common vulnerable services
        vulnerable_ports = {
            21: "FTP - Check for anonymous login",
            23: "Telnet - Unencrypted communication", 
            135: "RPC - Potential MSRPC vulnerabilities",
            139: "NetBIOS - Information disclosure",
            445: "SMB - EternalBlue potential",
            3389: "RDP - BlueKeep potential"
        }
        
        for port, description in vulnerable_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    vulnerabilities.append(f"Port {port}: {description}")
                    print(f"{Colors.RED}[!] {description}{Colors.END}")
            except:
                pass
        
        # Web vulnerabilities
        try:
            response = urllib.request.urlopen(f"http://{self.target}", timeout=5)
            headers = dict(response.headers)
            
            if 'Server' in headers:
                print(f"{Colors.YELLOW}[!] Server header exposed: {headers['Server']}{Colors.END}")
                vulnerabilities.append(f"Server info exposed: {headers['Server']}")
                
            security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
            for header in security_headers:
                if header not in headers:
                    print(f"{Colors.YELLOW}[!] Missing security header: {header}{Colors.END}")
                    vulnerabilities.append(f"Missing security header: {header}")
                    
        except:
            pass
            
        if not vulnerabilities:
            print(f"{Colors.GREEN}[+] No obvious vulnerabilities detected{Colors.END}")
        else:
            print(f"{Colors.RED}[!] Found {len(vulnerabilities)} potential issues{Colors.END}")

    # WEB SECURITY AUDIT - FULLY WORKING
    def web_security_audit(self):
        if not self.target:
            print(f"{Colors.RED}[!] No target set!{Colors.END}")
            return
            
        self.print_menu_header("WEB SECURITY AUDIT")
        
        url = self.target
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            
        print(f"{Colors.CYAN}[*] Auditing {url}...{Colors.END}")
        
        try:
            # Bypass SSL verification for testing
            context = ssl._create_unverified_context()
            response = urllib.request.urlopen(url, timeout=10, context=context)
            headers = dict(response.headers)
            
            print(f"\n{Colors.YELLOW}=== SECURITY HEADERS ANALYSIS ==={Colors.END}")
            
            # Check security headers
            security_checks = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTP Strict Transport Security',
                'Content-Security-Policy': 'Content Security Policy',
                'X-XSS-Protection': 'Cross-site scripting protection'
            }
            
            for header, description in security_checks.items():
                if header in headers:
                    print(f"{Colors.GREEN}[✓] {header}: {headers[header]}{Colors.END}")
                else:
                    print(f"{Colors.RED}[✗] {header}: MISSING - {description}{Colors.END}")
            
            # Server information
            if 'Server' in headers:
                print(f"{Colors.YELLOW}[!] Server: {headers['Server']}{Colors.END}")
                
            # Check for common files
            print(f"\n{Colors.YELLOW}=== DIRECTORY CHECK ==={Colors.END}")
            common_files = ['robots.txt', '.htaccess', 'backup.zip', 'admin.php', 'config.php']
            
            for file in common_files:
                try:
                    test_url = f"{url}/{file}"
                    urllib.request.urlopen(test_url, timeout=5, context=context)
                    print(f"{Colors.RED}[!] Found: {test_url}{Colors.END}")
                except:
                    print(f"{Colors.GREEN}[-] Not found: {file}{Colors.END}")
                    
        except Exception as e:
            print(f"{Colors.RED}[!] Web audit failed: {str(e)}{Colors.END}")

    # PASSWORD TOOLS - FULLY WORKING
    def password_tools_menu(self):
        while True:
            self.print_menu_header("PASSWORD TOOLS")
            
            options = [
                f"{Colors.CYAN}1{Colors.END}. Password Strength Checker",
                f"{Colors.CYAN}2{Colors.END}. Hash Generator", 
                f"{Colors.CYAN}3{Colors.END}. Hash Cracker",
                f"{Colors.CYAN}4{Colors.END}. Password Generator",
                f"{Colors.CYAN}0{Colors.END}. Back to Main Menu"
            ]
            
            for option in options:
                print(f"{Colors.PURPLE}║ {option:<56} ║{Colors.END}")
            print(f"{Colors.PURPLE}╚{'═' * 60}╝{Colors.END}")
            
            choice = input(f"\n{Colors.CYAN}[?] SELECT TOOL {Colors.YELLOW}>>{Colors.END} ").strip()
            
            if choice == '1':
                self.password_strength_checker()
            elif choice == '2':
                self.hash_generator()
            elif choice == '3':
                self.hash_cracker()
            elif choice == '4':
                self.password_generator()
            elif choice == '0':
                break
            else:
                print(f"{Colors.RED}[!] Invalid choice!{Colors.END}")

    def password_strength_checker(self):
        password = input(f"{Colors.CYAN}[?] Enter password to check {Colors.YELLOW}>>{Colors.END} ").strip()
        
        if not password:
            return
            
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Too short (min 8 characters)")
            
        # Lowercase and uppercase
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("❌ Need both lowercase and uppercase letters")
            
        # Numbers
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("❌ Add numbers (0-9)")
            
        # Special characters
        if any(not c.isalnum() for c in password):
            score += 1
        else:
            feedback.append("❌ Add special characters (!@#$% etc.)")
        
        # Strength assessment
        strength_levels = {
            0: f"{Colors.RED}VERY WEAK - Easily crackable{Colors.END}",
            1: f"{Colors.RED}WEAK - Basic protection{Colors.END}", 
            2: f"{Colors.YELLOW}MEDIUM - Moderate protection{Colors.END}",
            3: f"{Colors.GREEN}STRONG - Good protection{Colors.END}",
            4: f"{Colors.GREEN}{Colors.BOLD}VERY STRONG - Excellent protection{Colors.END}"
        }
        
        print(f"\n{Colors.CYAN}Password Analysis:{Colors.END}")
        print(f"Strength: {strength_levels.get(score, 'UNKNOWN')}")
        print(f"Length: {len(password)} characters")
        
        if feedback:
            print(f"\n{Colors.YELLOW}Recommendations:{Colors.END}")
            for item in feedback:
                print(f"  {item}")

    def hash_generator(self):
        text = input(f"{Colors.CYAN}[?] Enter text to hash {Colors.YELLOW}>>{Colors.END} ").strip()
        
        if not text:
            return
            
        md5_hash = hashlib.md5(text.encode()).hexdigest()
        sha1_hash = hashlib.sha1(text.encode()).hexdigest()
        sha256_hash = hashlib.sha256(text.encode()).hexdigest()
        
        print(f"\n{Colors.CYAN}Generated Hashes:{Colors.END}")
        print(f"MD5:    {md5_hash}")
        print(f"SHA1:   {sha1_hash}")
        print(f"SHA256: {sha256_hash}")

    def hash_cracker(self):
        hash_value = input(f"{Colors.CYAN}[?] Enter hash to crack {Colors.YELLOW}>>{Colors.END} ").strip()
        hash_type = input(f"{Colors.CYAN}[?] Hash type (md5/sha1/sha256) {Colors.YELLOW}>>{Colors.END} ").strip().lower()
        
        if not hash_value or not hash_type:
            return
            
        common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master",
            "12345678", "123456789", "12345", "1234", "111111"
        ]
        
        print(f"{Colors.YELLOW}[*] Cracking hash...{Colors.END}")
        
        for password in common_passwords:
            test_hash = ""
            if hash_type == 'md5':
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == 'sha1':
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == 'sha256':
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            else:
                print(f"{Colors.RED}[!] Unsupported hash type{Colors.END}")
                return
                
            if test_hash == hash_value:
                print(f"{Colors.GREEN}[SUCCESS] Password found: {password}{Colors.END}")
                return
                
        print(f"{Colors.RED}[FAILED] Password not found in common wordlist{Colors.END}")

    def password_generator(self):
        try:
            length = int(input(f"{Colors.CYAN}[?] Password length {Colors.YELLOW}>>{Colors.END} ") or 12)
        except:
            length = 12
            
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        password = ''.join(random.choice(chars) for _ in range(length))
        
        print(f"\n{Colors.GREEN}Generated Password: {password}{Colors.END}")

    # SYSTEM INFORMATION - FULLY WORKING
    def system_information(self):
        self.print_menu_header("SYSTEM INFORMATION")
        
        print(f"{Colors.CYAN}=== NETWORK INFORMATION ==={Colors.END}")
        try:
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"Hostname: {hostname}")
            print(f"Local IP: {local_ip}")
            
            # Get external IP
            try:
                external_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf-8')
                print(f"External IP: {external_ip}")
            except:
                print("External IP: Could not determine")
                
        except Exception as e:
            print(f"Error: {str(e)}")
            
        print(f"\n{Colors.CYAN}=== TOOL INFORMATION ==={Colors.END}")
        print(f"Session ID: {self.session_id}")
        print(f"Current Target: {self.target if self.target else 'None'}")
        print(f"Python Version: {sys.version.split()[0]}")

    # GODMODE FULL SCAN - FULLY WORKING
    def godmode_full_scan(self):
        if not self.target:
            print(f"{Colors.RED}[!] No target set!{Colors.END}")
            return
            
        self.print_menu_header("GODMODE FULL SCAN")
        print(f"{Colors.RED}[!] INITIATING FULL SCAN ON {self.target}{Colors.END}")
        
        scan_functions = [
            ("Port Scanning", self.fast_port_scanner),
            ("Service Detection", self.service_detection),
            ("Vulnerability Assessment", self.vulnerability_scanner),
            ("Web Security Audit", self.web_security_audit)
        ]
        
        for scan_name, scan_function in scan_functions:
            print(f"\n{Colors.YELLOW}=== {scan_name} ==={Colors.END}")
            try:
                scan_function()
                time.sleep(1)
            except Exception as e:
                print(f"{Colors.RED}[!] {scan_name} failed: {str(e)}{Colors.END}")
                
        print(f"\n{Colors.GREEN}[+] GodMode scan completed!{Colors.END}")

    def exit_toolkit(self):
        print(f"\n{Colors.RED}{Colors.BOLD}")
        print("    ╔══════════════════════════════════════════════════╗")
        print("    ║               CYBER-NEXUS SESSION END           ║")
        print("    ║                                                  ║")
        print("    ║         [ GODMODE DEACTIVATED ]                 ║")
        print(f"    ║         Session: {self.session_id}                ║")
        print("    ║         Created by KAECILIUS404                 ║")
        print("    ║                                                  ║")
        print("    ║           Stay Ethical. Stay Secure.            ║")
        print("    ╚══════════════════════════════════════════════════╝")
        print(Colors.END)
        sys.exit(0)

def main():
    try:
        CyberNexusGodMode()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Cyber-Nexus terminated by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Critical error: {str(e)}{Colors.END}")

if __name__ == "__main__":
    main()