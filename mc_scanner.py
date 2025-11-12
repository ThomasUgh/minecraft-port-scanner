#!/usr/bin/env python3
"""
MC Server Scanner - A comprehensive Minecraft server scanner
Supports port scanning (TCP/UDP) and server status via API
Author: Your Name
GitHub: https://github.com/yourusername/mc-server-scanner
"""

import socket
import sys
import argparse
import json
import time
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict
import requests
from colorama import init, Fore, Style

init(autoreset=True)

DEFAULT_PORT_START = 25000
DEFAULT_PORT_END = 26000
DEFAULT_TIMEOUT = 0.5
MAX_THREADS = 150
API_BASE_URL = "https://api.mcsrvstat.us/3/"

PORT_RANGES = {
    'default': (25000, 26000),
    'java': (25565, 25565),
    'bedrock': (19132, 19132),
    'geyser': (19100, 19900),
    'bungeecord': (25577, 25577),
    'velocity': (25565, 25577),
    'common': (25565, 25600),
    'extended': (25000, 30000),
    'full': (19000, 30000),
}

class Colors:
    """Color codes for terminal output"""
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    WARNING = Fore.YELLOW
    INFO = Fore.CYAN
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class MCServerScanner:
    """Main class for Minecraft server scanning operations"""
    
    def __init__(self, timeout: float = DEFAULT_TIMEOUT, threads: int = MAX_THREADS):
        self.timeout = timeout
        self.threads = min(threads, MAX_THREADS)
        self.open_ports = []
        self.lock = threading.Lock()
        
    def scan_tcp_port(self, host: str, port: int) -> bool:
        """
        Scan a single TCP port with Minecraft-specific detection
        
        Args:
            host: Target IP address
            port: Port number to scan
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                try:
                    if port in [19132, 19133] or port in range(19100, 19900):
                        sock.close()
                        return True
                    
                    if port == 25565 or port in range(25000, 26000):
                        sock.close()
                        return True
                    
                    sock.close()
                    return True
                except:
                    sock.close()
                    return True
            else:
                sock.close()
                return False
        except socket.error:
            return False
    
    def scan_udp_port(self, host: str, port: int) -> bool:
        """
        Scan a single UDP port (Minecraft Bedrock/Query Protocol)
        
        Args:
            host: Target IP address
            port: Port number to scan
            
        Returns:
            True if port responds, False otherwise
        """
        if port == 19132 or port in range(19100, 19900):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Bedrock/RakNet unconnected ping packet
                bedrock_ping = bytes([
                    0x01,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    # OFFLINE_MESSAGE_DATA_ID (magic bytes)
                    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
                    0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
                    # Client GUID
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ])
                
                sock.sendto(bedrock_ping, (host, port))
                
                try:
                    data, _ = sock.recvfrom(4096)
                    sock.close()
                    if len(data) > 0 and data[0] == 0x1c:
                        return True
                except socket.timeout:
                    sock.close()
            except Exception:
                pass
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            query_packet = b'\xFE\xFD\x09\x01\x02\x03\x04'
            sock.sendto(query_packet, (host, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return len(data) > 0
            except socket.timeout:
                sock.close()
        except Exception:
            pass
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'\x00', (host, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return len(data) > 0
            except socket.timeout:
                sock.close()
        except Exception:
            pass
        
        return False
    
    def scan_port_worker(self, host: str, port: int, protocol: str) -> Optional[Tuple[int, str]]:
        """
        Worker function for port scanning
        
        Args:
            host: Target IP address
            port: Port number to scan
            protocol: 'tcp', 'udp', or 'both'
            
        Returns:
            Tuple of (port, protocol) if open, None otherwise
        """
        results = []
        
        if protocol in ['tcp', 'both']:
            if self.scan_tcp_port(host, port):
                results.append((port, 'TCP'))
                
        if protocol in ['udp', 'both']:
            if self.scan_udp_port(host, port):
                results.append((port, 'UDP'))
        
        return results if results else None
    
    def scan_range(self, host: str, start_port: int, end_port: int, protocol: str = 'both') -> List[Tuple[int, str]]:
        """
        Scan a range of ports using multiple threads
        
        Args:
            host: Target IP address
            start_port: Starting port number
            end_port: Ending port number
            protocol: 'tcp', 'udp', or 'both'
            
        Returns:
            List of tuples containing (port, protocol) for open ports
        """
        if protocol == 'both':
            if (start_port <= 19132 <= end_port) or \
               (start_port >= 19100 and end_port <= 19900):
                print(f"{Colors.WARNING}[!] Detected Bedrock/Geyser port range - using both TCP and UDP")
                protocol = 'both'
        
        print(f"\n{Colors.INFO}[*] Starting port scan on {host}")
        print(f"{Colors.INFO}[*] Port range: {start_port}-{end_port}")
        print(f"{Colors.INFO}[*] Protocol: {protocol.upper()}")
        print(f"{Colors.INFO}[*] Threads: {self.threads}")
        print(f"{Colors.INFO}[*] Timeout: {self.timeout}s")
        
        if (start_port <= 19132 <= end_port) or (start_port >= 19100 and end_port <= 19900):
            print(f"{Colors.WARNING}[!] Note: Bedrock servers primarily use UDP protocol\n")
        else:
            print("")
        
        open_ports = []
        total_ports = end_port - start_port + 1
        scanned = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_port_worker, host, port, protocol): port
                for port in range(start_port, end_port + 1)
            }
            
            for future in as_completed(futures):
                scanned += 1
                port = futures[future]
                
                # Progress indicator
                progress = (scanned / total_ports) * 100
                sys.stdout.write(f'\r{Colors.INFO}[*] Progress: {progress:.1f}% ({scanned}/{total_ports})')
                sys.stdout.flush()
                
                try:
                    result = future.result()
                    if result:
                        for port_info in result:
                            open_ports.append(port_info)
                            port_num, proto = port_info
                            # Add port type hint
                            port_hint = ""
                            if port_num == 25565:
                                port_hint = " (Java Edition)"
                            elif port_num == 19132:
                                port_hint = " (Bedrock Edition)"
                            elif port_num in range(19100, 19900):
                                port_hint = " (Geyser/Bedrock)"
                            elif port_num == 25577:
                                port_hint = " (BungeeCord)"
                            print(f'\n{Colors.SUCCESS}[+] Found open port: {port_num}/{proto}{port_hint}')
                except Exception as e:
                    print(f'\n{Colors.ERROR}[-] Error scanning port {port}: {e}')
        
        print(f'\n\n{Colors.INFO}[*] Scan complete!')
        return sorted(open_ports, key=lambda x: x[0])
    
    def get_server_status(self, address: str) -> Dict:
        """
        Get Minecraft server status using mcsrvstat.us API
        
        Args:
            address: Server address (IP or domain)
            
        Returns:
            Dictionary containing server information
        """
        try:
            url = f"{API_BASE_URL}{address}"
            response = requests.get(url, timeout=5)
            data = response.json()
            
            if data.get('online'):
                data['edition'] = 'Java'
                return data
            
            url = f"{API_BASE_URL}bedrock/{address}"
            response = requests.get(url, timeout=5)
            data = response.json()
            
            if data.get('online'):
                data['edition'] = 'Bedrock'
                return data
            
            return {'online': False, 'address': address}
            
        except requests.RequestException as e:
            print(f"{Colors.ERROR}[-] API Error: {e}")
            return {'online': False, 'error': str(e)}
    
    def resolve_domain(self, domain: str) -> Optional[str]:
        """
        Resolve domain to IP address
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
    
    def display_server_info(self, data: Dict):
        """
        Display formatted server information
        
        Args:
            data: Server information dictionary from API
        """
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"{Colors.BOLD}SERVER INFORMATION")
        print(f"{Colors.BOLD}{'='*60}\n")
        
        if data.get('online'):
            print(f"{Colors.SUCCESS}✓ Server is ONLINE")
            print(f"\n{Colors.INFO}Address: {data.get('hostname', 'N/A')}:{data.get('port', 'N/A')}")
            print(f"{Colors.INFO}IP: {data.get('ip', 'N/A')}")
            print(f"{Colors.INFO}Edition: {data.get('edition', 'Unknown')}")
            
            # Add protocol hint based on port
            port = data.get('port', 0)
            if port == 19132:
                print(f"{Colors.WARNING}Protocol: UDP/TCP (Bedrock Edition)")
            elif port in range(19100, 19900):
                print(f"{Colors.WARNING}Protocol: UDP/TCP (Geyser/Bedrock)")
            elif port == 25565:
                print(f"{Colors.WARNING}Protocol: TCP (Java Edition)")
            
            # Version info
            version = data.get('version', 'Unknown')
            print(f"{Colors.INFO}Version: {version}")
            
            # Player info
            players = data.get('players', {})
            online_players = players.get('online', 0)
            max_players = players.get('max', 0)
            print(f"{Colors.INFO}Players: {online_players}/{max_players}")
            
            # Player list if available
            player_list = players.get('list', [])
            if player_list:
                print(f"\n{Colors.INFO}Online Players:")
                for player in player_list[:10]:  # Show max 10 players
                    if isinstance(player, dict):
                        print(f"  • {player.get('name', 'Unknown')}")
                    else:
                        print(f"  • {player}")
                if len(player_list) > 10:
                    print(f"  ... and {len(player_list) - 10} more")
            
            motd = data.get('motd', {})
            if motd:
                if isinstance(motd, dict):
                    clean_motd = motd.get('clean', [])
                    if clean_motd:
                        print(f"\n{Colors.INFO}MOTD:")
                        for line in clean_motd:
                            print(f"  {line}")
                else:
                    print(f"\n{Colors.INFO}MOTD: {motd}")
            
            software = data.get('software', 'Unknown')
            if software != 'Unknown':
                print(f"\n{Colors.INFO}Software: {software}")
            
            mods = data.get('mods', [])
            if mods:
                print(f"\n{Colors.INFO}Mods/Plugins ({len(mods)}):")
                for mod in mods[:5]:
                    print(f"  • {mod}")
                if len(mods) > 5:
                    print(f"  ... and {len(mods) - 5} more")
        else:
            print(f"{Colors.ERROR}✗ Server is OFFLINE or not responding")
            if data.get('error'):
                print(f"{Colors.ERROR}Error: {data['error']}")
        
        print(f"\n{Colors.BOLD}{'='*60}\n")
    
    def test_bedrock_server(self, host: str, port: int = 19132) -> bool:
        """
        Special test for Bedrock servers with detailed output
        
        Args:
            host: Server address
            port: Port to test (default: 19132)
            
        Returns:
            True if Bedrock server found
        """
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"{Colors.BOLD}BEDROCK SERVER TEST")
        print(f"{Colors.BOLD}{'='*60}\n")
        
        print(f"{Colors.INFO}[*] Testing {host}:{port}")
        print(f"{Colors.INFO}[*] Timeout: {self.timeout}s\n")
        
        # Test UDP (primary for Bedrock)
        print(f"{Colors.INFO}[1/3] Testing UDP connection...")
        udp_result = self.scan_udp_port(host, port)
        if udp_result:
            print(f"{Colors.SUCCESS}  ✓ UDP port {port} is responding (Bedrock detected!)")
        else:
            print(f"{Colors.WARNING}  ✗ UDP port {port} not responding")
        
        # Test TCP (secondary)
        print(f"{Colors.INFO}[2/3] Testing TCP connection...")
        tcp_result = self.scan_tcp_port(host, port)
        if tcp_result:
            print(f"{Colors.SUCCESS}  ✓ TCP port {port} is open")
        else:
            print(f"{Colors.WARNING}  ✗ TCP port {port} not open")
        
        # Try API
        print(f"{Colors.INFO}[3/3] Checking server status via API...")
        data = self.get_server_status(f"{host}:{port}")
        if data.get('online'):
            print(f"{Colors.SUCCESS}  ✓ Server information retrieved")
        else:
            print(f"{Colors.WARNING}  ✗ No API response")
        
        # Results
        print(f"\n{Colors.BOLD}Results:")
        print(f"{Colors.BOLD}{'='*40}")
        
        if udp_result or tcp_result:
            print(f"{Colors.SUCCESS}✓ Bedrock server detected!")
            if not udp_result:
                print(f"{Colors.WARNING}  ⚠ UDP not responding (may be firewall issue)")
            if not tcp_result:
                print(f"{Colors.INFO}  ℹ TCP not open (normal for some servers)")
            return True
        else:
            print(f"{Colors.ERROR}✗ No Bedrock server detected on port {port}")
            print(f"\n{Colors.WARNING}Troubleshooting tips:")
            print(f"  • Increase timeout: add '-t 2.0' or '-t 3.0'")
            print(f"  • Check firewall allows UDP traffic")
            print(f"  • Verify server is online")
            print(f"  • Try alternative ports: 19133, 19134")
            print(f"  • Try Geyser range: 19100-19900")
            return False

def print_banner():
    """Print application banner"""
    banner = f"""
{Colors.BOLD}{Colors.INFO}
╔══════════════════════════════════════════════════════════╗
║                MC SERVER SCANNER v1.0                     ║
║            Minecraft Server Port Scanner & API            ║
║                   GitHub: @yourusername                   ║
╚══════════════════════════════════════════════════════════╝

{Colors.WARNING}Predefined Port Ranges:{Colors.RESET}
  • default    : 25000-26000 (Default range)
  • java       : 25565       (Standard Java Edition)
  • bedrock    : 19132       (Standard Bedrock Edition)
  • geyser     : 19100-19900 (Geyser/Bedrock range)
  • bungeecord : 25577       (BungeeCord proxy)
  • velocity   : 25565-25577 (Velocity proxy)
  • common     : 25565-25600 (Common servers)
  • extended   : 25000-30000 (Extended range)
  • full       : 19000-30000 (Full scan range)
{Colors.RESET}
"""
    print(banner)

def main():
    """Main function"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='MC Server Scanner - Comprehensive Minecraft server scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan 192.168.1.1                    # Scan default port range (25000-26000)
  %(prog)s scan 192.168.1.1 -r geyser          # Scan Geyser/Bedrock ports (19100-19900)
  %(prog)s scan 192.168.1.1 -r java            # Scan standard Java port (25565)
  %(prog)s scan 192.168.1.1 -r bedrock         # Scan standard Bedrock port (19132)
  %(prog)s scan 192.168.1.1 -r full            # Full scan (19000-30000)
  %(prog)s scan 192.168.1.1 -p 25565-25575     # Scan custom port range
  %(prog)s scan example.com --tcp              # Scan only TCP ports
  %(prog)s status play.example.com             # Get server status via API
  %(prog)s status example.com --scan -r geyser # Get status and scan Geyser ports
  %(prog)s bedrock-test play.example.com       # Test specifically for Bedrock server
  %(prog)s bedrock-test 192.168.1.1 -p 19133   # Test Bedrock on specific port
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    scan_parser = subparsers.add_parser('scan', help='Scan port range for Minecraft servers')
    scan_parser.add_argument('target', help='Target IP address or domain')
    scan_parser.add_argument('-p', '--ports', default='default',
                           help='Port range: START-END, single PORT, or preset (default/java/bedrock/geyser/etc.)')
    scan_parser.add_argument('-r', '--range', choices=list(PORT_RANGES.keys()),
                           help='Use predefined port range')
    scan_parser.add_argument('--tcp', action='store_true', help='Scan only TCP ports')
    scan_parser.add_argument('--udp', action='store_true', help='Scan only UDP ports')
    scan_parser.add_argument('-t', '--timeout', type=float, default=DEFAULT_TIMEOUT,
                           help=f'Connection timeout in seconds (default: {DEFAULT_TIMEOUT})')
    scan_parser.add_argument('--threads', type=int, default=MAX_THREADS,
                           help=f'Number of threads (default: {MAX_THREADS})')
    
    status_parser = subparsers.add_parser('status', help='Get server status via API')
    status_parser.add_argument('server', help='Server address (IP:port or domain)')
    status_parser.add_argument('--scan', action='store_true',
                             help='Also perform port scan after getting status')
    status_parser.add_argument('-p', '--ports', default='default',
                             help='Port range: START-END, single PORT, or preset (default/java/bedrock/geyser/etc.)')
    status_parser.add_argument('-r', '--range', choices=list(PORT_RANGES.keys()),
                             help='Use predefined port range for scanning')
    
    interactive_parser = subparsers.add_parser('interactive', help='Interactive mode')
    
    bedrock_parser = subparsers.add_parser('bedrock-test', help='Test specifically for Bedrock servers')
    bedrock_parser.add_argument('server', help='Server address (IP or domain)')
    bedrock_parser.add_argument('-p', '--port', type=int, default=19132,
                              help='Port to test (default: 19132)')
    bedrock_parser.add_argument('-t', '--timeout', type=float, default=2.0,
                              help='Connection timeout in seconds (default: 2.0)')
    
    args = parser.parse_args()
    
    scanner = MCServerScanner()
    
    if args.mode == 'scan':
        if args.tcp and not args.udp:
            protocol = 'tcp'
        elif args.udp and not args.tcp:
            protocol = 'udp'
        else:
            protocol = 'both'
        
        port_range = args.range if hasattr(args, 'range') and args.range else args.ports
        
        try:
            if port_range in PORT_RANGES:
                start_port, end_port = PORT_RANGES[port_range]
                print(f"{Colors.INFO}[*] Using predefined range '{port_range}': {start_port}-{end_port}")
            elif ',' in port_range:
                ports_to_scan = []
                for port_str in port_range.split(','):
                    port_str = port_str.strip()
                    if '-' in port_str:
                        start, end = map(int, port_str.split('-'))
                        ports_to_scan.extend(range(start, end + 1))
                    else:
                        ports_to_scan.append(int(port_str))

                start_port = min(ports_to_scan)
                end_port = max(ports_to_scan)
                print(f"{Colors.INFO}[*] Scanning specific ports: {port_range}")
            elif '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
        except (ValueError, KeyError):
            print(f"{Colors.ERROR}[-] Invalid port range format. Use: START-END, single PORT, comma-separated, or predefined range name")
            print(f"{Colors.INFO}[*] Available presets: {', '.join(PORT_RANGES.keys())}")
            sys.exit(1)
        
        target = args.target
        if not target.replace('.', '').isdigit():
            print(f"{Colors.INFO}[*] Resolving domain: {target}")
            ip = scanner.resolve_domain(target)
            if ip:
                print(f"{Colors.SUCCESS}[+] Resolved to: {ip}")
                target = ip
            else:
                print(f"{Colors.ERROR}[-] Failed to resolve domain")
                sys.exit(1)
        
        scanner.timeout = args.timeout
        scanner.threads = args.threads
        
        start_time = time.time()
        open_ports = scanner.scan_range(target, start_port, end_port, protocol)
        scan_time = time.time() - start_time
        
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"{Colors.BOLD}SCAN RESULTS")
        print(f"{Colors.BOLD}{'='*60}\n")
        
        if open_ports:
            print(f"{Colors.SUCCESS}[+] Found {len(open_ports)} open port(s):\n")
            for port, proto in open_ports:
                print(f"    {Colors.SUCCESS}• Port {port}/{proto}")
        else:
            print(f"{Colors.WARNING}[!] No open ports found in range {start_port}-{end_port}")
        
        print(f"\n{Colors.INFO}[*] Scan completed in {scan_time:.2f} seconds")
        print(f"{Colors.BOLD}{'='*60}\n")
        
    elif args.mode == 'status':
        # Get server status
        print(f"{Colors.INFO}[*] Fetching server status for: {args.server}")
        data = scanner.get_server_status(args.server)
        scanner.display_server_info(data)
        
        if args.scan and data.get('ip'):
            print(f"{Colors.INFO}[*] Starting port scan on resolved IP: {data['ip']}\n")
            
            port_range = args.range if hasattr(args, 'range') and args.range else args.ports
            
            try:
                if port_range in PORT_RANGES:
                    start_port, end_port = PORT_RANGES[port_range]
                    print(f"{Colors.INFO}[*] Using predefined range '{port_range}': {start_port}-{end_port}")
                elif '-' in port_range:
                    start_port, end_port = map(int, port_range.split('-'))
                else:
                    start_port = end_port = int(port_range)
            except (ValueError, KeyError):
                print(f"{Colors.ERROR}[-] Invalid port range format")
                print(f"{Colors.INFO}[*] Available presets: {', '.join(PORT_RANGES.keys())}")
                sys.exit(1)
            
            open_ports = scanner.scan_range(data['ip'], start_port, end_port)
            
            if open_ports:
                print(f"\n{Colors.SUCCESS}[+] Additional open ports found:")
                for port, proto in open_ports:
                    if port != data.get('port', 25565):
                        print(f"    • Port {port}/{proto}")
    
    elif args.mode == 'interactive':
        while True:
            print(f"\n{Colors.BOLD}Select operation:")
            print("1. Scan port range")
            print("2. Get server status")
            print("3. Get status + port scan")
            print("4. Exit")
            
            try:
                choice = input(f"\n{Colors.INFO}Enter choice (1-4): {Colors.RESET}")
                
                if choice == '1':
                    target = input(f"{Colors.INFO}Enter target IP/domain: {Colors.RESET}")
                    
                    print(f"\n{Colors.INFO}Available port ranges:")
                    for name, (start, end) in PORT_RANGES.items():
                        print(f"  • {name:12} : {start:5}-{end:5}")
                    
                    ports = input(f"\n{Colors.INFO}Enter port range (name/range/PORT) [default]: {Colors.RESET}").strip()
                    
                    if not ports:
                        ports = "default"
                    
                    if ports in PORT_RANGES:
                        start_port, end_port = PORT_RANGES[ports]
                        print(f"{Colors.SUCCESS}[+] Using range '{ports}': {start_port}-{end_port}")
                    else:
                        try:
                            if '-' in ports:
                                start_port, end_port = map(int, ports.split('-'))
                            else:
                                start_port = end_port = int(ports)
                        except ValueError:
                            print(f"{Colors.ERROR}[-] Invalid port range")
                            continue
                    
                    protocol = input(f"{Colors.INFO}Protocol (tcp/udp/both) [both]: {Colors.RESET}").lower()
                    if protocol not in ['tcp', 'udp']:
                        protocol = 'both'
                    
                    # Resolve domain if needed
                    if not target.replace('.', '').isdigit():
                        print(f"{Colors.INFO}[*] Resolving domain...")
                        ip = scanner.resolve_domain(target)
                        if ip:
                            print(f"{Colors.SUCCESS}[+] Resolved to: {ip}")
                            target = ip
                        else:
                            print(f"{Colors.ERROR}[-] Failed to resolve domain")
                            continue
                    
                    open_ports = scanner.scan_range(target, start_port, end_port, protocol)
                    
                    if open_ports:
                        print(f"\n{Colors.SUCCESS}[+] Found open ports:")
                        for port, proto in open_ports:
                            print(f"    • Port {port}/{proto}")
                    else:
                        print(f"{Colors.WARNING}[!] No open ports found")
                
                elif choice == '2':
                    server = input(f"{Colors.INFO}Enter server address: {Colors.RESET}")
                    data = scanner.get_server_status(server)
                    scanner.display_server_info(data)
                
                elif choice == '3':
                    server = input(f"{Colors.INFO}Enter server address: {Colors.RESET}")
                    data = scanner.get_server_status(server)
                    scanner.display_server_info(data)
                    
                    if data.get('ip'):
                        scan_choice = input(f"{Colors.INFO}Scan ports on {data['ip']}? (y/n): {Colors.RESET}")
                        if scan_choice.lower() == 'y':
                            print(f"\n{Colors.INFO}Available port ranges:")
                            for name, (start, end) in PORT_RANGES.items():
                                print(f"  • {name:12} : {start:5}-{end:5}")
                            
                            ports = input(f"\n{Colors.INFO}Enter port range (name/range/PORT) [default]: {Colors.RESET}").strip()
                            if not ports:
                                ports = "default"
                            
                            try:
                                if ports in PORT_RANGES:
                                    start_port, end_port = PORT_RANGES[ports]
                                    print(f"{Colors.SUCCESS}[+] Using range '{ports}': {start_port}-{end_port}")
                                elif '-' in ports:
                                    start_port, end_port = map(int, ports.split('-'))
                                else:
                                    start_port = end_port = int(ports)
                                
                                open_ports = scanner.scan_range(data['ip'], start_port, end_port)
                                
                                if open_ports:
                                    print(f"\n{Colors.SUCCESS}[+] Found open ports:")
                                    for port, proto in open_ports:
                                        print(f"    • Port {port}/{proto}")
                            except ValueError:
                                print(f"{Colors.ERROR}[-] Invalid port range")
                
                elif choice == '4':
                    print(f"{Colors.INFO}[*] Exiting...")
                    break
                
                else:
                    print(f"{Colors.WARNING}[!] Invalid choice")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.INFO}[*] Exiting...")
                break
            except Exception as e:
                print(f"{Colors.ERROR}[-] Error: {e}")
    
    elif args.mode == 'bedrock-test':
        target = args.server
        port = args.port
        
        if not target.replace('.', '').isdigit():
            print(f"{Colors.INFO}[*] Resolving domain: {target}")
            ip = scanner.resolve_domain(target)
            if ip:
                print(f"{Colors.SUCCESS}[+] Resolved to: {ip}")
                target = ip
            else:
                print(f"{Colors.ERROR}[-] Failed to resolve domain")
                sys.exit(1)
        
        scanner.timeout = args.timeout
        result = scanner.test_bedrock_server(target, port)
        
        if not result and port == 19132:
            print(f"\n{Colors.INFO}[*] Testing alternative Bedrock ports...")
            alt_ports = [19133, 19134]
            for alt_port in alt_ports:
                print(f"\n{Colors.INFO}Testing port {alt_port}...")
                if scanner.scan_udp_port(target, alt_port) or scanner.scan_tcp_port(target, alt_port):
                    print(f"{Colors.SUCCESS}✓ Found Bedrock server on port {alt_port}!")
                    break
    
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.INFO}[*] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.ERROR}[-] Unexpected error: {e}")
        sys.exit(1)
