"""NetOwl - Network Device Scanner and OS Fingerprinter."""

from __future__ import annotations

import csv
import ipaddress
import logging
import os
import queue
import socket
import sys
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Ether,
    ICMP,
    IP,
    RadioTap,
    TCP,
    UDP,
    sniff,
    sr1,
    srp,
)
from scapy.error import Scapy_Exception


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
)
LOGGER = logging.getLogger("netowl")


LEGACY_MAC_VENDOR_DB: Dict[str, str] = {
    "00:0A:95": "Samsung Electronics",
    "00:15:5D": "Microsoft Corporation",
    "00:1A:11": "Apple, Inc.",
    "00:1B:63": "Apple, Inc.",
    "00:1C:B3": "Cisco Systems",
    "00:1D:D8": "Dell Inc.",
    "00:1F:16": "Dell Inc.",
    "00:22:48": "Samsung Electronics",
    "00:24:E8": "LG Electronics",
    "00:25:9C": "Hewlett-Packard",
    "00:26:B0": "Hewlett-Packard",
    "00:50:56": "VMware, Inc.",
    "00:90:A9": "Intel Corporate",
    "00:E0:4C": "Realtek Semiconductor",
    "04:C7:2D": "Amazon Technologies",
    "08:00:27": "Oracle Corporation (VirtualBox)",
    "3C:5A:B4": "Google, Inc.",
    "4C:D7:17": "HP Inc.",
    "40:9C:28": "Amazon Technologies",
    "44:65:0D": "Huawei Technologies",
    "58:EF:68": "Microsoft Corporation",
    "5C:52:30": "Apple, Inc.",
    "60:45:BD": "Xiaomi Communications",
    "6C:0B:5E": "Brother Industries, LTD.",
    "70:5D:CC": "ASUSTek Computer",
    "80:19:34": "Hon Hai Precision",
    "80:38:FB": "Google, Inc.",
    "88:AE:1D": "Sony Corporation",
    "A0:36:9F": "Lenovo Mobile",
    "B8:27:EB": "Raspberry Pi Foundation",
    "C8:60:00": "Intel Corporate",
    "CC:46:D6": "Samsung Electronics",
    "D0:37:45": "Google Nest",
    "DC:A6:32": "ASUSTeK Computer Inc.",
    "F0:9F:C2": "TP-Link Technologies",
}


def normalize_mac(mac_address: str) -> str:
    """Return a normalized, uppercase MAC address."""

    hex_only = "".join(char for char in mac_address if char.isalnum())
    hex_only = hex_only.upper()
    if len(hex_only) != 12:
        return mac_address.upper()
    pairs = [hex_only[i : i + 2] for i in range(0, 12, 2)]
    return ":".join(pairs)


class MacVendorLookup:
    """High-performance MAC vendor resolver backed by a JSON OUI database."""

    def __init__(self, vendor_file: Path, fallback: Dict[str, str]) -> None:
        self.vendor_file = vendor_file
        self.fallback = fallback
        self.prefix_tables: Dict[int, Dict[str, str]] = {}
        self.prefix_lengths: List[int] = []
        self._lock = threading.Lock()
        self._loaded = False
        self._load_failed = False
        self._seed_fallback()
        self._start_background_load()

    @staticmethod
    def _sanitize_prefix(prefix: str) -> str:
        return "".join(ch for ch in prefix if ch.isalnum()).upper()

    def _seed_fallback(self) -> None:
        """Seed the lookup tables with the baked-in fallback prefixes."""

        for prefix, vendor in self.fallback.items():
            sanitized = self._sanitize_prefix(prefix)
            if not sanitized:
                continue
            length = len(sanitized)
            self.prefix_tables.setdefault(length, {})[sanitized] = vendor
        self.prefix_lengths = sorted(self.prefix_tables.keys(), reverse=True)

    def _start_background_load(self) -> None:
        """Kick off asynchronous loading of the vendor database."""

        if not self.vendor_file.exists():
            LOGGER.warning(
                "MAC vendor database not found at %s; falling back to baked-in prefixes.",
                self.vendor_file,
            )
            self._load_failed = True
            return

        threading.Thread(
            target=self._load_from_disk_background,
            name="MacVendorLoader",
            daemon=True,
        ).start()

    def _load_from_disk_background(self) -> None:
        """Load the large vendor database from disk without blocking the UI."""

        try:
            tree = ET.parse(str(self.vendor_file))
            root = tree.getroot()
            # Handle namespace from Cisco XML format
            ns = {'spt': 'http://www.cisco.com/server/spt'}
            mappings = root.findall('.//spt:VendorMapping', ns)
            # Fallback if namespace doesn't match
            if not mappings:
                mappings = root.findall('.//{http://www.cisco.com/server/spt}VendorMapping')
            if not mappings:
                # Try without namespace
                mappings = root.findall('.//VendorMapping')
        except (OSError, ET.ParseError) as exc:
            LOGGER.warning(
                "Failed to load MAC vendor database from %s: %s; falling back to baked-in prefixes.",
                self.vendor_file,
                exc,
            )
            with self._lock:
                self._load_failed = True
            return

        staged_tables: Dict[int, Dict[str, str]] = {}
        loaded_count = 0
        for mapping in mappings:
            prefix = mapping.get('mac_prefix')
            vendor = mapping.get('vendor_name')
            if not prefix or not vendor:
                continue
            sanitized = self._sanitize_prefix(prefix)
            if not sanitized:
                continue
            length = len(sanitized)
            staged_tables.setdefault(length, {})[sanitized] = vendor.strip() or "Unknown"
            loaded_count += 1

        with self._lock:
            for length, mapping in staged_tables.items():
                self.prefix_tables.setdefault(length, {}).update(mapping)
            self.prefix_lengths = sorted(self.prefix_tables.keys(), reverse=True)
            self._loaded = True

        LOGGER.info(
            "Loaded %d vendor prefixes from %s (prefix lengths: %s)",
            loaded_count,
            self.vendor_file,
            ", ".join(str(length) for length in self.prefix_lengths),
        )

    def lookup_vendor(self, mac_or_prefix: str) -> str:
        """Resolve a vendor name for the supplied MAC address or prefix."""

        if not mac_or_prefix:
            return "Unknown"

        sanitized = self._sanitize_prefix(mac_or_prefix)
        if not sanitized:
            return "Unknown"

        with self._lock:
            for length in self.prefix_lengths:
                if len(sanitized) < length:
                    continue
                vendor = self.prefix_tables.get(length, {}).get(sanitized[:length])
                if vendor:
                    return vendor
        return "Unknown"


_mac_vendor_lookup = MacVendorLookup(
    vendor_file=Path(__file__).with_name("vendorMacs.xml"),
    fallback=LEGACY_MAC_VENDOR_DB,
)


def is_locally_administered_mac(mac_address: str) -> bool:
    """Check if a MAC address is locally administered (LAA).
    
    LAA addresses have the second bit of the first octet set to 1.
    These are virtual/randomized MACs not in the OUI database.
    Examples: x2, x6, xA, xE in the second hex digit.
    """
    if not mac_address or len(mac_address) < 2:
        return False
    
    # Get first octet (first two hex chars after sanitization)
    sanitized = ''.join(ch for ch in mac_address if ch.isalnum()).upper()
    if len(sanitized) < 2:
        return False
    
    try:
        first_octet = int(sanitized[:2], 16)
        # Check bit 1 (0x02) of first octet
        return bool(first_octet & 0x02)
    except ValueError:
        return False


def get_vendor(mac_address: str) -> str:
    """Return the vendor for the provided MAC address using a trie-like lookup."""

    normalized = normalize_mac(mac_address)
    
    # Check if it's a locally administered address (virtual/randomized MAC)
    if is_locally_administered_mac(normalized):
        return "Locally Administered (Virtual MAC)"
    
    vendor = _mac_vendor_lookup.lookup_vendor(normalized)
    return vendor if vendor != "Unknown" else "Unknown Vendor"


@dataclass
class NetworkDevice:
    """Data container for information about a network device."""

    ip: Optional[str]
    mac: str
    hostname: Optional[str] = None
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    ttl: Optional[int] = None

    def summary(self) -> str:
        """Render a concise summary string for list presentation."""

        ip_part = self.ip or "Unknown IP"
        parts = [ip_part, self.mac]
        if self.hostname:
            parts.append(self.hostname)
        elif self.vendor != "Unknown":
            parts.append(self.vendor)
        return " | ".join(parts)


@dataclass
class WiFiNetwork:
    """Data container for WiFi network information."""

    ssid: str
    bssid: str
    channel: int
    signal_strength: int = 0
    encryption: str = "Unknown"
    
    def summary(self) -> str:
        """Render a concise summary string for list presentation."""
        
        signal_bars = "▂▄▆█"[min(3, max(0, (self.signal_strength + 100) // 25))]
        return f"{self.ssid} | {signal_bars} | Ch {self.channel} | {self.encryption}"


def get_local_ip_address() -> Optional[str]:
    """Discover the preferred outbound IP address for the host."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError as exc:
        LOGGER.debug("UDP discovery failed: %s", exc)
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except OSError as exc:
        LOGGER.error("Unable to resolve local hostname: %s", exc)
        return None


def get_local_network_range(cidr: int = 24) -> Optional[str]:
    """Compute the local network range in CIDR notation."""

    local_ip = get_local_ip_address()
    if not local_ip:
        return None
    try:
        network = ipaddress.ip_network(f"{local_ip}/{cidr}", strict=False)
    except ValueError as exc:
        LOGGER.error("Invalid network derived from %s: %s", local_ip, exc)
        return None
    return str(network)


def get_ip_from_arp_cache(mac: str) -> Optional[str]:
    """Try to resolve an IP address for `mac` from the OS ARP cache (Linux /proc/net/arp).

    This is fast and non-blocking; return None if not present.
    """

    try:
        normalized = normalize_mac(mac).lower()
        if os.name == "posix":
            arp_path = Path("/proc/net/arp")
            if arp_path.exists():
                for line in arp_path.read_text().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip, hw_type, flags, hw_addr = parts[0], parts[1], parts[2], parts[3]
                        if normalize_mac(hw_addr).lower() == normalized:
                            return ip
    except Exception:
        LOGGER.debug("Unable to read ARP cache for mac=%s", mac)
    return None


def arp_scan(network_range: str, timeout: int = 2) -> List[NetworkDevice]:
    """Execute an ARP scan across the provided network range."""

    devices: Dict[str, NetworkDevice] = {}
    try:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
        # Multiple retries for better device discovery
        answered, _ = srp(request, timeout=timeout, retry=2, verbose=False)
        for _sent, received in answered:
            ip_address = received[ARP].psrc
            mac_address = normalize_mac(received[ARP].hwsrc)
            devices[mac_address] = NetworkDevice(
                ip=ip_address,
                mac=mac_address,
                vendor=get_vendor(mac_address),
            )
    except Scapy_Exception as exc:
        LOGGER.error("ARP scan failed: %s", exc)
    except OSError as exc:
        LOGGER.error("Socket error during ARP scan: %s", exc)
    return list(devices.values())


def guess_os_from_ttl(ttl: int) -> str:
    """Infer an operating system family from a TTL value.
    
    Common initial TTL values for devices on the same local network (0 hops):
    - 64: Linux, Unix, macOS, Android, iOS
    - 128: Windows (all modern versions)
    - 255: Cisco IOS, network devices, Solaris
    
    TTL decreases by 1 for each router hop. Since most devices are on the
    same local network, we check for exact values first, then nearby values
    accounting for a few hops.
    """
    
    # Exact match - same local network (0 hops)
    if ttl == 64:
        return "Linux / Unix / macOS / Android / iOS"
    elif ttl == 128:
        return "Windows"
    elif ttl == 255:
        return "Cisco IOS / Network Device / Solaris"
    
    # Close to 64 (1-9 hops away)
    elif 55 <= ttl <= 63:
        return "Linux / Unix / macOS / Android / iOS (distant)"
    
    # Close to 128 (1-9 hops away)
    elif 119 <= ttl <= 127:
        return "Windows (distant)"
    
    # Close to 255 (1-9 hops away)
    elif 246 <= ttl <= 254:
        return "Cisco IOS / Network Device (distant)"
    
    # Between ranges - likely 64-initial with many hops
    elif 33 <= ttl <= 54:
        return "Linux / Unix (many hops)"
    
    # Between 128 and 255 - likely 255-initial with hops
    elif 129 <= ttl <= 245:
        return "Network Device (many hops)"
    
    # Very low TTL - likely 64-initial with many hops
    elif 1 <= ttl <= 32:
        return "Linux / Unix (very distant)"
    
    else:
        return f"Unknown (TTL={ttl})"


def tcp_syn_probe(target_ip: str, port: int = 80, timeout: int = 2) -> Optional[int]:
    """Probe a target host with a TCP SYN packet and return the TTL from response.
    
    This uses Scapy to send a TCP SYN packet and extract the TTL value from
    the IP header of the response (either SYN-ACK or RST).
    """

    try:
        # Craft TCP SYN packet
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Send packet and wait for response
        response = sr1(packet, timeout=timeout, verbose=False)
        
        # Extract TTL from IP layer if present
        if response and response.haslayer(IP):
            ttl_value = int(response[IP].ttl)
            LOGGER.debug("TTL probe for %s:%d -> TTL=%d", target_ip, port, ttl_value)
            return ttl_value
            
    except Scapy_Exception as exc:
        LOGGER.debug("Scapy error during TCP probe for %s:%s - %s", target_ip, port, exc)
    except OSError as exc:
        LOGGER.debug("Socket error during TCP probe for %s:%s - %s",
                     target_ip, port, exc)
    except Exception as exc:
        LOGGER.debug("Unexpected error during TCP probe for %s:%s - %s",
                     target_ip, port, exc)
    return None


def icmp_ping_probe(target_ip: str, timeout: int = 2) -> Optional[int]:
    """Probe a target host with an ICMP Echo Request and return the TTL.
    
    This uses Scapy to send an ICMP Echo Request (ping) and extract the TTL
    value from the IP header of the Echo Reply.
    """
    
    try:
        # Craft ICMP Echo Request packet
        packet = IP(dst=target_ip) / ICMP()
        
        # Send packet and wait for response
        response = sr1(packet, timeout=timeout, verbose=False)
        
        # Extract TTL from IP layer if present
        if response and response.haslayer(IP):
            ttl_value = int(response[IP].ttl)
            LOGGER.debug("ICMP probe for %s -> TTL=%d", target_ip, ttl_value)
            return ttl_value
            
    except Scapy_Exception as exc:
        LOGGER.debug("Scapy error during ICMP probe for %s - %s", target_ip, exc)
    except OSError as exc:
        LOGGER.debug("Socket error during ICMP probe for %s - %s", target_ip, exc)
    except Exception as exc:
        LOGGER.debug("Unexpected error during ICMP probe for %s - %s", target_ip, exc)
    return None


def multi_probe_ttl(target_ip: str) -> Optional[int]:
    """Use multiple probe techniques to get TTL value for more reliable OS detection.
    
    Tries in order with very short timeouts:
    1. TCP SYN to port 80 (HTTP) - fastest, most common
    2. TCP SYN to port 443 (HTTPS) - if port 80 fails
    
    Returns the first successful TTL value obtained.
    """
    
    # Try port 80 first (fastest, most common)
    ttl = tcp_syn_probe(target_ip, port=80, timeout=0.5)
    if ttl is not None:
        return ttl
    
    # Try port 443 as backup
    ttl = tcp_syn_probe(target_ip, port=443, timeout=0.5)
    if ttl is not None:
        return ttl
    
    return None


def fingerprint_devices(devices: List[NetworkDevice]) -> List[NetworkDevice]:
    """Augment devices with TTL-based OS fingerprinting."""

    for device in devices:
        ttl = tcp_syn_probe(device.ip) if device.ip else None
        if ttl is None:
            ttl = tcp_syn_probe(device.ip, port=443, timeout=1) if device.ip else None
        if ttl is not None:
            device.ttl = ttl
            device.os_guess = guess_os_from_ttl(ttl)
    return devices


def full_network_scan(network_range: Optional[str] = None) -> List[NetworkDevice]:
    """Perform ARP discovery and OS fingerprinting across the network."""

    target_range = network_range or get_local_network_range()
    if not target_range:
        raise RuntimeError("Unable to determine local network range.")
    LOGGER.info("Starting ARP scan on %s", target_range)
    devices = arp_scan(target_range, timeout=2)
    LOGGER.info("ARP scan complete: %d device(s) discovered", len(devices))
    return devices


def fast_initial_scan(network_range: Optional[str] = None) -> List[NetworkDevice]:
    """Perform fast initial scan with very short timeout for quick results."""
    
    target_range = network_range or get_local_network_range()
    if not target_range:
        raise RuntimeError("Unable to determine local network range.")
    LOGGER.info("Starting fast initial scan on %s", target_range)
    # Very short timeout for first batch
    devices = arp_scan(target_range, timeout=1)
    LOGGER.info("Fast initial scan: %d device(s) found", len(devices))
    return devices


def deep_scan(network_range: Optional[str] = None) -> List[NetworkDevice]:
    """Perform thorough scan with longer timeout to find more devices."""
    
    target_range = network_range or get_local_network_range()
    if not target_range:
        raise RuntimeError("Unable to determine local network range.")
    LOGGER.info("Starting deep scan on %s", target_range)
    # Two passes with moderate timeout for better discovery
    all_devices = {}
    
    for pass_num in range(2):
        LOGGER.info("Deep scan pass %d/2", pass_num + 1)
        devices = arp_scan(target_range, timeout=3)
        for device in devices:
            # Keep existing or add new
            if device.mac not in all_devices:
                all_devices[device.mac] = device
            elif device.ip and not all_devices[device.mac].ip:
                # Update IP if we found one
                all_devices[device.mac].ip = device.ip
    
    LOGGER.info("Deep scan complete: %d total devices", len(all_devices))
    return list(all_devices.values())


def scan_wifi_networks(duration: int = 10) -> List[WiFiNetwork]:
    """Scan for nearby WiFi networks by sniffing beacon frames."""

    networks: Dict[str, WiFiNetwork] = {}
    
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            try:
                bssid = packet[Dot11].addr2
                if not bssid:
                    return
                
                # Extract SSID
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                if not ssid:
                    ssid = "<Hidden SSID>"
                
                # Extract channel
                channel = 0
                stats = packet[Dot11Beacon].network_stats()
                if 'channel' in stats:
                    channel = stats['channel']
                
                # Extract signal strength
                signal_strength = -100
                if packet.haslayer(RadioTap):
                    if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                        signal_strength = packet[RadioTap].dBm_AntSignal
                
                # Determine encryption
                capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                encryption = "Open"
                if "privacy" in capability.lower():
                    # Check for WPA/WPA2
                    crypto = set()
                    p = packet[Dot11Elt]
                    while isinstance(p, Dot11Elt):
                        if p.ID == 48:  # RSN IE (WPA2)
                            crypto.add("WPA2")
                        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA IE
                            crypto.add("WPA")
                        p = p.payload
                    if crypto:
                        encryption = "/".join(sorted(crypto))
                    else:
                        encryption = "WEP"
                
                # Update or add network
                if bssid not in networks:
                    networks[bssid] = WiFiNetwork(
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        signal_strength=signal_strength,
                        encryption=encryption,
                    )
                else:
                    # Update signal strength if stronger
                    if signal_strength > networks[bssid].signal_strength:
                        networks[bssid].signal_strength = signal_strength
            except Exception as exc:
                LOGGER.debug("Failed to parse WiFi packet: %s", exc)
    
    try:
        LOGGER.info("Starting WiFi scan for %d seconds", duration)
        sniff(iface=None, prn=packet_handler, timeout=duration, store=False)
        LOGGER.info("WiFi scan complete: %d network(s) discovered", len(networks))
    except Scapy_Exception as exc:
        LOGGER.error("WiFi scan failed: %s", exc)
    except OSError as exc:
        LOGGER.error("WiFi scan socket error: %s", exc)
    
    return list(networks.values())


def ensure_admin_privileges(root: tk.Tk) -> None:
    """Enforce administrative privileges required by Scapy."""

    if os.name == "nt":
        is_admin = False
        if ctypes is not None:
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except OSError:
                is_admin = False
    else:
        is_admin = os.geteuid() == 0
    if not is_admin:
        messagebox.showerror(
            "Administrator Privileges Required",
            (
                "NetOwl must be run with sudo/administrator privileges "
                "for Scapy operations."
            ),
        )
        root.destroy()
        sys.exit(1)


class NetOwlApp:
    """Tkinter application wrapper for NetOwl."""

    BG_WHITE = "#ffffff"
    BG_GRAY_LIGHT = "#f0f0f0"
    BG_GRAY_MEDIUM = "#cccccc"
    FG_BLACK = "#000000"

    FONT_MONO = "Consolas"
    FONT_SIZE_REGULAR = 12
    FONT_SIZE_EMPHASIS = 14

    FRAME_PADDING = 10
    WIDGET_PADDING = 5

    EVENT_SCAN_RESULT = "scan_result"
    EVENT_SCAN_ERROR = "scan_error"
    EVENT_SCAN_COMPLETE = "scan_complete"
    EVENT_HOSTNAME_UPDATE = "hostname_update"
    EVENT_FINGERPRINT_RESULT = "fingerprint_result"
    EVENT_IP_FOUND = "ip_found"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("NetOwl - Network Device Scanner")
        self.root.configure(bg=self.BG_WHITE)
        
        self._apply_starting_geometry()

        self.devices_by_mac: Dict[str, NetworkDevice] = {}
        self.ordered_devices: List[NetworkDevice] = []
        self.filtered_devices: List[NetworkDevice] = []
        self.current_selection_mac: Optional[str] = None
        self.scanning = False
        self.last_scan_count = 0
        self.last_scan_failed = False
        self.search_query = ""
        self._refresh_pending = False  # Throttle UI refreshes
        self.event_queue: queue.Queue[Tuple[str, Optional[object]]] = queue.Queue()
        self.fingerprint_queue: queue.Queue[Tuple[str, Optional[str]]] = queue.Queue()
        self.pending_fingerprint: Set[str] = set()
        self.pending_ip_lookup: Set[str] = set()
        self._fingerprint_lock = threading.Lock()

        self._configure_style()
        self._build_ui()

        self.passive_listener_thread: Optional[threading.Thread] = None
        self.fingerprint_worker: threading.Thread = threading.Thread(
            target=self._fingerprint_worker,
            name="FingerprintWorker",
            daemon=True,
        )
        self.fingerprint_worker.start()
        self._start_passive_listener()
        self._process_event_queue()
        
        # Start periodic IP resolution checker (every 5 seconds)
        self._schedule_ip_resolution()
        
        # Start with a quick scan for immediate results, then passive listening continues
        self.root.after(500, self._auto_start_scan)

    def _configure_style(self) -> None:
        """Configure ttk styles to enforce the strict visual identity."""

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            LOGGER.debug("Falling back to default ttk theme.")

        style.configure(
            "App.TFrame",
            background=self.BG_WHITE,
        )
        
        # Configure Treeview for table-like appearance with borders
        style.configure(
            "Treeview",
            rowheight=35,
            font=(self.FONT_MONO, 11),
            background=self.BG_WHITE,
            foreground=self.FG_BLACK,
            fieldbackground=self.BG_WHITE,
            borderwidth=1,
            relief="solid",
        )
        style.configure(
            "Treeview.Heading",
            font=(self.FONT_MONO, 11, "bold"),
            background=self.BG_GRAY_LIGHT,
            foreground=self.FG_BLACK,
            borderwidth=1,
            relief="raised",
        )
        style.map("Treeview", background=[("selected", self.BG_GRAY_MEDIUM)])
        style.configure(
            "App.TLabel",
            background=self.BG_WHITE,
            foreground=self.FG_BLACK,
            font=(self.FONT_MONO, self.FONT_SIZE_REGULAR),
        )
        style.configure(
            "Title.TLabel",
            background=self.BG_WHITE,
            foreground=self.FG_BLACK,
            font=(self.FONT_MONO, self.FONT_SIZE_EMPHASIS, "bold"),
        )
        style.configure(
            "Flat.TButton",
            background=self.BG_WHITE,
            foreground=self.FG_BLACK,
            font=(self.FONT_MONO, self.FONT_SIZE_REGULAR),
            borderwidth=0,
            relief="flat",
            padding=(10, 5),
        )
        style.map(
            "Flat.TButton",
            background=[("active", self.BG_GRAY_MEDIUM)],
            foreground=[("active", self.FG_BLACK)],
        )
        style.configure(
            "Details.TFrame",
            background=self.BG_GRAY_LIGHT,
            relief="flat",
            borderwidth=0,
        )
        style.configure(
            "DetailsKey.TLabel",
            background=self.BG_GRAY_LIGHT,
            foreground=self.FG_BLACK,
            font=(self.FONT_MONO, self.FONT_SIZE_EMPHASIS, "bold"),
        )
        style.configure(
            "DetailsValue.TLabel",
            background=self.BG_GRAY_LIGHT,
            foreground=self.FG_BLACK,
            font=(self.FONT_MONO, self.FONT_SIZE_REGULAR),
        )

    def _build_ui(self) -> None:
        """Construct the main layout for the application."""

        main_frame = ttk.Frame(self.root, style="App.TFrame", padding=self.FRAME_PADDING)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._build_title(main_frame)
        self._build_controls(main_frame)
        self._build_content(main_frame)

    def _build_title(self, parent: ttk.Frame) -> None:
        """Render the heading area."""

        title_frame = ttk.Frame(parent, style="App.TFrame", padding=(0, 0, 0, self.FRAME_PADDING))
        title_frame.pack(fill=tk.X)

        title_label = ttk.Label(
            title_frame,
            text="NetOwl - Network Scanner",
            style="Title.TLabel",
        )
        title_label.pack(anchor=tk.W)

    def _build_controls(self, parent: ttk.Frame) -> None:
        """Create the scan controls and status indicators."""

        controls = ttk.Frame(parent, style="App.TFrame", padding=(0, 0, 0, self.FRAME_PADDING))
        controls.pack(fill=tk.X)

        # Top row: Scan and action buttons
        top_row = ttk.Frame(controls, style="App.TFrame")
        top_row.pack(fill=tk.X, pady=(0, self.WIDGET_PADDING))

        # Scan button
        self.scan_button = ttk.Button(
            top_row,
            text="Scan Network",
            style="Flat.TButton",
            command=self._on_scan_requested,
        )
        self.scan_button.pack(side=tk.LEFT, padx=(0, self.WIDGET_PADDING), pady=self.WIDGET_PADDING)

        # Export button
        self.export_button = ttk.Button(
            top_row,
            text="Export to CSV",
            style="Flat.TButton",
            command=self._export_to_csv,
        )
        self.export_button.pack(side=tk.LEFT, padx=(0, self.WIDGET_PADDING), pady=self.WIDGET_PADDING)

        # Status on the right
        status_frame = ttk.Frame(top_row, style="App.TFrame", padding=self.FRAME_PADDING)
        status_frame.pack(side=tk.RIGHT, fill=tk.X)

        status_label = ttk.Label(status_frame, text="Status:", style="App.TLabel")
        status_label.pack(side=tk.LEFT, padx=(0, self.WIDGET_PADDING), pady=self.WIDGET_PADDING)

        self.status_value = ttk.Label(status_frame, text="Listening for devices...", style="App.TLabel")
        self.status_value.pack(side=tk.LEFT, pady=self.WIDGET_PADDING)

        # Bottom row: Search bar
        search_row = ttk.Frame(controls, style="App.TFrame")
        search_row.pack(fill=tk.X)

        search_label = ttk.Label(search_row, text="Search:", style="App.TLabel")
        search_label.pack(side=tk.LEFT, padx=(0, self.WIDGET_PADDING))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._on_search_changed())
        
        self.search_entry = ttk.Entry(
            search_row,
            textvariable=self.search_var,
            font=(self.FONT_MONO, self.FONT_SIZE_REGULAR),
            width=40,
        )
        self.search_entry.pack(side=tk.LEFT, padx=(0, self.WIDGET_PADDING))

        clear_search_btn = ttk.Button(
            search_row,
            text="Clear",
            style="Flat.TButton",
            command=self._clear_search,
        )
        clear_search_btn.pack(side=tk.LEFT)

    def _build_content(self, parent: ttk.Frame) -> None:
        """Lay out the device list and details panel."""

        content = ttk.Frame(parent, style="App.TFrame", padding=self.FRAME_PADDING)
        content.pack(fill=tk.BOTH, expand=True)

        # Devices view
        self._build_devices_view(content)

    def _build_devices_view(self, parent: ttk.Frame) -> None:
        """Build the network devices view with Treeview for large device lists."""

        list_frame = ttk.Frame(parent, style="App.TFrame", padding=self.FRAME_PADDING)
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(list_frame, style="App.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, self.WIDGET_PADDING))
        
        list_label = ttk.Label(header_frame, text="Discovered Devices:", style="App.TLabel")
        list_label.pack(side=tk.LEFT)
        
        self.device_count_label = ttk.Label(header_frame, text="(0 devices)", style="App.TLabel")
        self.device_count_label.pack(side=tk.LEFT, padx=(5, 0))

        # Treeview for devices with columns
        tree_frame = ttk.Frame(list_frame, style="App.TFrame")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        scrollbar_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.device_tree = ttk.Treeview(
            tree_frame,
            columns=("ip", "mac", "hostname", "vendor", "os"),
            show="headings",
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set,
            selectmode="browse",
            height=25,
        )
        
        # Apply table styling
        self.device_tree.tag_configure("oddrow", background="#FFFFFF")
        self.device_tree.tag_configure("evenrow", background="#F5F5F5")
        
        # Configure columns with better widths
        self.device_tree.column("ip", width=130, minwidth=110, stretch=True)
        self.device_tree.column("mac", width=150, minwidth=140, stretch=True)
        self.device_tree.column("hostname", width=280, minwidth=180, stretch=True)
        self.device_tree.column("vendor", width=160, minwidth=120, stretch=True)
        self.device_tree.column("os", width=200, minwidth=140, stretch=True)
        
        # Configure headings
        self.device_tree.heading("ip", text="IP Address", anchor=tk.W)
        self.device_tree.heading("mac", text="MAC Address", anchor=tk.W)
        self.device_tree.heading("hostname", text="Hostname", anchor=tk.W)
        self.device_tree.heading("vendor", text="Vendor", anchor=tk.W)
        self.device_tree.heading("os", text="Operating System", anchor=tk.W)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_tree_selected)
        
        scrollbar_y.configure(command=self.device_tree.yview)
        scrollbar_x.configure(command=self.device_tree.xview)

        details_wrapper = ttk.Frame(parent, style="App.TFrame", padding=self.FRAME_PADDING)
        details_wrapper.pack(side=tk.RIGHT, fill=tk.Y)

        details_label = ttk.Label(details_wrapper, text="Device Details:", style="App.TLabel")
        details_label.pack(anchor=tk.W, pady=(0, self.WIDGET_PADDING))

        details_frame = ttk.Frame(details_wrapper, style="Details.TFrame", padding=self.FRAME_PADDING)
        details_frame.pack(fill=tk.BOTH, expand=True)

        keys = [
            ("ip", "IP Address"),
            ("mac", "MAC Address"),
            ("hostname", "Hostname"),
            ("vendor", "Vendor"),
            ("os", "Operating System"),
            ("ttl", "TTL Value"),
        ]
        self.details_values: Dict[str, ttk.Label] = {}
        for row, (key, label_text) in enumerate(keys):
            key_label = ttk.Label(details_frame, text=f"{label_text}:", style="DetailsKey.TLabel")
            key_label.grid(row=row, column=0, sticky=tk.NW, padx=(0, self.WIDGET_PADDING), pady=self.WIDGET_PADDING)

            value_label = ttk.Label(details_frame, text="--", style="DetailsValue.TLabel", wraplength=350, justify=tk.LEFT)
            value_label.grid(row=row, column=1, sticky=tk.W, pady=self.WIDGET_PADDING)
            self.details_values[key] = value_label

        details_frame.columnconfigure(1, weight=1)

    def _start_passive_listener(self) -> None:
        """Launch the passive hostname listener in a daemon thread."""

        if self.passive_listener_thread and self.passive_listener_thread.is_alive():
            return

        def target() -> None:
            LOGGER.info("Starting passive hostname listener.")
            try:
                sniff(
                    filter="udp port 67 or udp port 68 or udp port 5353",
                    prn=self._handle_passive_packet,
                    store=False,
                )
            except Scapy_Exception as exc:
                LOGGER.error("Passive listener stopped unexpectedly: %s", exc)
            except OSError as exc:
                LOGGER.error("Passive listener socket error: %s", exc)

        self.passive_listener_thread = threading.Thread(target=target, daemon=True)
        self.passive_listener_thread.start()

    def _handle_passive_packet(self, packet) -> None:
        """Parse sniffed packets and queue hostname updates."""

        try:
            update = self._extract_hostname_update(packet)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOGGER.debug("Failed to parse passive packet: %s", exc)
            return
        if update is None:
            return
        self.event_queue.put((self.EVENT_HOSTNAME_UPDATE, update))

    @staticmethod
    def _extract_hostname_update(packet) -> Optional[Dict[str, Optional[str]]]:
        """Extract hostname information from DHCP or mDNS packets."""

        if not packet.haslayer(Ether):
            return None
        mac_address = normalize_mac(packet[Ether].src)
        ip_address: Optional[str] = None
        hostname: Optional[str] = None

        if packet.haslayer(IP):
            ip_address = packet[IP].src

        if packet.haslayer(BOOTP):
            bootp_layer = packet[BOOTP]
            for candidate in (bootp_layer.yiaddr, bootp_layer.ciaddr):
                if candidate and candidate != "0.0.0.0":
                    ip_address = candidate
                    break

        if packet.haslayer(DHCP):
            for option in packet[DHCP].options:
                if isinstance(option, tuple) and option[0] == "hostname":
                    value = option[1]
                    if isinstance(value, bytes):
                        value = value.decode(errors="ignore")
                    hostname = value.strip()
                    break
        elif packet.haslayer(DNS) and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            if udp_layer.sport == 5353 or udp_layer.dport == 5353:
                dns_layer = packet[DNS]
                if dns_layer.qdcount > 0 and dns_layer.qd:
                    qname = dns_layer.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode(errors="ignore")
                    hostname = qname.rstrip(".")
                elif dns_layer.ancount > 0 and dns_layer.an:
                    answer = dns_layer.an
                    qname = getattr(answer, "rrname", None)
                    if isinstance(qname, bytes):
                        qname = qname.decode(errors="ignore")
                    if qname:
                        hostname = str(qname).rstrip(".")

        if hostname:
            return {
                "mac": mac_address,
                "ip": ip_address,
                "hostname": hostname,
            }
        return None

    def _process_event_queue(self) -> None:
        """Handle queued worker-thread events on the Tkinter main loop."""

        while True:
            try:
                event, payload = self.event_queue.get_nowait()
            except queue.Empty:
                break
            if event == self.EVENT_SCAN_RESULT:
                self._handle_scan_result(payload)
            elif event == self.EVENT_SCAN_ERROR:
                self._handle_scan_error(payload)
            elif event == self.EVENT_SCAN_COMPLETE:
                self._handle_scan_complete()
            elif event == self.EVENT_HOSTNAME_UPDATE:
                self._handle_hostname_update(payload)
            elif event == self.EVENT_FINGERPRINT_RESULT:
                self._handle_fingerprint_result(payload)
            elif event == self.EVENT_IP_FOUND:
                self._handle_ip_found(payload)
        self.root.after(150, self._process_event_queue)

    def _handle_scan_result(self, payload) -> None:
        """Merge scan results into the device registry."""

        if not isinstance(payload, list):
            return
        self.last_scan_count = len(payload)
        for device in payload:
            normalized_mac = normalize_mac(device.mac)
            device.mac = normalized_mac
            device.vendor = get_vendor(normalized_mac)
            existing = self.devices_by_mac.get(normalized_mac)
            if existing:
                # Always update IP if scan found one
                if device.ip and device.ip != "0.0.0.0":
                    existing.ip = device.ip
                existing.os_guess = device.os_guess
                existing.ttl = device.ttl
                # Update vendor if we have better info
                if existing.vendor in ("Unknown", "Unknown Vendor") and device.vendor not in ("Unknown", "Unknown Vendor"):
                    existing.vendor = device.vendor
            else:
                # For new devices, try ARP cache if scan didn't find IP
                if not device.ip or device.ip == "0.0.0.0":
                    ip_from_cache = get_ip_from_arp_cache(normalized_mac)
                    if ip_from_cache and ip_from_cache != "0.0.0.0":
                        device.ip = ip_from_cache
                self.devices_by_mac[normalized_mac] = device
            
            # Queue fingerprinting for devices with IPs
            if device.ip and device.ip != "0.0.0.0":
                self._queue_fingerprint(device)
            elif existing and existing.ip and existing.ip != "0.0.0.0":
                self._queue_fingerprint(existing)
                
        self._refresh_device_listbox()

    def _handle_scan_error(self, payload) -> None:
        """Display scan errors and reset UI state."""

        self.last_scan_failed = True
        self.status_value.configure(text="Scan failed.")
        if isinstance(payload, str):
            messagebox.showerror("Scan Failed", payload)

    def _handle_scan_complete(self) -> None:
        """Finalize UI state after a scan completes."""

        self.scanning = False
        self.scan_button.state(["!disabled"])
        if self.last_scan_failed:
            self.last_scan_failed = False
            return
        if self.last_scan_count == 0:
            self.status_value.configure(text="Scan complete. No devices found.")
        else:
            plural = "s" if self.last_scan_count != 1 else ""
            self.status_value.configure(
                text=f"Scan complete. Found {self.last_scan_count} device{plural}."
            )

    def _handle_hostname_update(self, payload: Optional[Dict[str, Optional[str]]]) -> None:
        """Apply passive hostname updates to tracked devices."""

        if not payload:
            return
        mac_address = payload.get("mac")
        if not mac_address:
            return
        normalized_mac = normalize_mac(mac_address)
        hostname = payload.get("hostname")
        ip_address = payload.get("ip")

        device = self.devices_by_mac.get(normalized_mac)
        if device is None:
            # Try to get IP from ARP cache immediately for new devices
            if not ip_address or ip_address == "0.0.0.0":
                ip_address = get_ip_from_arp_cache(normalized_mac)
            
            device = NetworkDevice(
                ip=ip_address,
                mac=normalized_mac,
                hostname=hostname,
                vendor=get_vendor(normalized_mac),
            )
            self.devices_by_mac[normalized_mac] = device
        else:
            if hostname:
                device.hostname = hostname
            if ip_address and ip_address != "0.0.0.0" and not device.ip:
                device.ip = ip_address

        # Always check ARP cache if IP is still unknown
        if not device.ip or device.ip == "0.0.0.0":
            ip_from_cache = get_ip_from_arp_cache(normalized_mac)
            if ip_from_cache and ip_from_cache != "0.0.0.0":
                device.ip = ip_from_cache

        # Queue fingerprinting if we have an IP
        if device.ip and device.ip != "0.0.0.0":
            self._queue_fingerprint(device)

        self._refresh_device_listbox()
        if self.current_selection_mac == normalized_mac:
            self._update_details_panel(device)

    def _handle_fingerprint_result(self, payload: Optional[Dict[str, Optional[object]]]) -> None:
        """Merge background fingerprint results into the device registry."""

        if not payload or not isinstance(payload, dict):
            return
        mac_address = payload.get("mac")
        if not mac_address:
            return
        device = self.devices_by_mac.get(mac_address)
        if not device:
            return

        ttl = payload.get("ttl")
        os_guess = payload.get("os_guess")

        if isinstance(ttl, int):
            device.ttl = ttl
        if isinstance(os_guess, str) and os_guess:
            device.os_guess = os_guess

        if self.current_selection_mac == mac_address:
            self._update_details_panel(device)
        self._refresh_device_listbox()

    def _handle_ip_found(self, payload: Optional[Dict[str, Optional[str]]]) -> None:
        """Apply discovered IP address for a MAC and update UI."""

        if not payload:
            return
        mac = payload.get("mac")
        ip = payload.get("ip")
        if not mac or not ip:
            return

        normalized = normalize_mac(mac)
        device = self.devices_by_mac.get(normalized)
        if not device:
            # Create minimal device entry
            device = NetworkDevice(ip=ip, mac=normalized, vendor=get_vendor(normalized))
            self.devices_by_mac[normalized] = device
        else:
            device.ip = ip

        # Queue fingerprinting now that we have an IP
        if ip and ip != "0.0.0.0":
            self._queue_fingerprint(device)

        # Refresh UI
        if self.current_selection_mac == normalized:
            self._update_details_panel(device)
        self._refresh_device_listbox()

    def _on_scan_requested(self) -> None:
        """Kick off a network scan via a worker thread."""

        if self.scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return
        self.scanning = True
        self.last_scan_count = 0
        self.last_scan_failed = False
        self.status_value.configure(text="Scanning devices... Preparing full results.")
        self.scan_button.state(["disabled"])

        thread = threading.Thread(target=self._run_scan, daemon=True)
        thread.start()
    
    def _auto_start_scan(self) -> None:
        """Automatically start scan on program launch."""
        
        if not self.scanning:
            self.status_value.configure(text="Scanning network...")
            self._on_scan_requested()

    def _run_scan(self) -> None:
        """Worker-thread entry point wrapping the scanning workflow."""

        try:
            devices = deep_scan()
            self.event_queue.put((self.EVENT_SCAN_RESULT, devices))
            
        except Exception as exc:
            LOGGER.exception("Network scan failed: %s", exc)
            message = (
                "Network scan failed. Ensure network connectivity and that "
                "you are running NetOwl with administrator privileges.\n\n"
                f"Details: {exc}"
            )
            self.event_queue.put((self.EVENT_SCAN_ERROR, message))
        finally:
            self.event_queue.put((self.EVENT_SCAN_COMPLETE, None))

    def _refresh_device_listbox(self) -> None:
        """Refresh the device list while preserving the active selection and scroll position.
        
        Uses throttling to prevent excessive refreshes with many devices.
        """
        
        # If refresh is already scheduled, skip this call
        if self._refresh_pending:
            return
        
        self._refresh_pending = True
        
        def do_refresh():
            """Actual refresh implementation."""
            self._refresh_pending = False
            
            selected_mac = self.current_selection_mac
            
            # Save current scroll position before clearing
            try:
                scroll_position = self.device_tree.yview()
            except Exception:
                scroll_position = None
                
            self.ordered_devices = sorted(
                self.devices_by_mac.values(),
                key=self._device_sort_key,
            )
            
            # Apply search filter
            if self.search_query:
                query_lower = self.search_query.lower()
                self.filtered_devices = [
                    device for device in self.ordered_devices
                    if query_lower in (device.ip or "").lower()
                    or query_lower in device.mac.lower()
                    or query_lower in (device.hostname or "").lower()
                    or query_lower in device.vendor.lower()
                    or query_lower in device.os_guess.lower()
                ]
            else:
                self.filtered_devices = self.ordered_devices
            
            # Clear tree
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            
            # Populate tree
            for idx, device in enumerate(self.filtered_devices, 1):
                # Clean and truncate hostname if too long for display
                hostname_display = device.hostname or "--"
                # Remove newlines and extra whitespace
                hostname_display = " ".join(hostname_display.split())
                if len(hostname_display) > 50:
                    hostname_display = hostname_display[:47] + "..."
                
                # Clean vendor and OS text
                vendor_display = " ".join((device.vendor or "Unknown").split())
                os_display = " ".join((device.os_guess or "Unknown").split())
                
                # Display IP (convert 0.0.0.0 to "Unknown")
                ip_display = device.ip if device.ip and device.ip != "0.0.0.0" else "Unknown"
                
                # Add distance indicator based on exact TTL values (local network = 0 hops)
                if device.ttl:
                    if device.ttl == 64:
                        os_display = f"🟢 {os_display}"  # Exact match: Linux/Mac/Android (local)
                    elif device.ttl == 128:
                        os_display = f"🔵 {os_display}"  # Exact match: Windows (local)
                    elif device.ttl == 255:
                        os_display = f"🔴 {os_display}"  # Exact match: Network device (local)
                    elif 55 <= device.ttl <= 63 or 119 <= device.ttl <= 127:
                        os_display = f"🟡 {os_display}"  # Close match (few hops)
                    else:
                        os_display = f"⚪ {os_display}"  # Distant or uncertain
                
                values = (
                    ip_display,
                    device.mac,
                    hostname_display,
                    vendor_display[:30],  # Limit vendor length
                    os_display[:40],  # Limit OS length
                )
                
                # Apply alternating row colors
                row_tag = "evenrow" if idx % 2 == 0 else "oddrow"
                item_id = self.device_tree.insert("", tk.END, values=values, tags=(device.mac, row_tag))
                
                if device.mac == selected_mac:
                    self.device_tree.selection_set(item_id)
                    # Don't auto-scroll to selected item - let user control scroll
            
            # Restore scroll position after refresh
            if scroll_position is not None:
                try:
                    self.device_tree.yview_moveto(scroll_position[0])
                except Exception:
                    pass
            
            # Update count label
            total = len(self.ordered_devices)
            filtered = len(self.filtered_devices)
            if total == filtered:
                self.device_count_label.configure(text=f"({total} device{'s' if total != 1 else ''})")
            else:
                self.device_count_label.configure(text=f"({filtered} of {total} device{'s' if total != 1 else ''})")
            
            if not self.filtered_devices:
                self._update_details_panel(None)
        
        # Schedule refresh after a short delay to batch multiple updates
        self.root.after(100, do_refresh)

    @staticmethod
    def _device_sort_key(device: NetworkDevice) -> Tuple[int, int, int, int, int, str]:
        """Provide a consistent sort key for devices - sorted by TTL (distance) then IP."""

        # Sort by TTL first (lower TTL = closer to you)
        ttl_value = device.ttl if device.ttl is not None else 999
        
        default_key = (999, 999, 999, 999)
        if device.ip:
            try:
                octets = [int(part) for part in device.ip.split(".")]
                if len(octets) == 4:
                    return (ttl_value, *octets, device.mac)
            except ValueError:
                LOGGER.debug("Non-numeric IP encountered: %s", device.ip)
        return (ttl_value, *default_key, device.mac)

    def _on_device_tree_selected(self, event) -> None:
        """Respond to user selection in the device tree."""

        selection = self.device_tree.selection()
        if not selection:
            self.current_selection_mac = None
            self._update_details_panel(None)
            return
        
        item_id = selection[0]
        tags = self.device_tree.item(item_id, "tags")
        if not tags:
            return
        
        mac_address = tags[0]
        device = self.devices_by_mac.get(mac_address)
        if device:
            self.current_selection_mac = device.mac
            
            # On-demand OS fingerprinting if not already done
            if device.ttl is None and device.ip:
                self._queue_fingerprint(device)
            # If IP is unknown, attempt to look it up in background
            if not device.ip:
                self._queue_ip_lookup(device.mac)
            
            self._update_details_panel(device)

    def _update_details_panel(self, device: Optional[NetworkDevice]) -> None:
        """Populate the details panel with device metadata."""

        details = {
            "ip": device.ip if device else "--",
            "mac": device.mac if device else "--",
            "hostname": device.hostname if device and device.hostname else "--",
            "vendor": device.vendor if device else "--",
            "os": device.os_guess if device else "--",
            "ttl": str(device.ttl) if device and device.ttl is not None else "--",
        }
        for key, widget in self.details_values.items():
            widget.configure(text=details.get(key, "--"))

    def _on_search_changed(self) -> None:
        """Handle search query changes."""
        
        self.search_query = self.search_var.get().strip()
        self._refresh_device_listbox()
    
    def _clear_search(self) -> None:
        """Clear the search field."""
        
        self.search_var.set("")

    def _apply_starting_geometry(self) -> None:
        """Determine a sensible default window size based on screen resolution."""

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        target_width = min(1600, int(screen_width * 0.85))
        target_height = min(950, int(screen_height * 0.85))

        offset_x = max(0, (screen_width - target_width) // 2)
        offset_y = max(0, (screen_height - target_height) // 3)

        self.root.geometry(f"{target_width}x{target_height}+{offset_x}+{offset_y}")
        self.root.minsize(min(1100, target_width), min(700, target_height))
    
    def _export_to_csv(self) -> None:
        """Export current device list to CSV."""
        
        if not self.ordered_devices:
            messagebox.showinfo("No Data", "No devices to export. Run a scan first.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"netowl_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        
        if not filename:
            return
        
        try:
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP Address", "MAC Address", "Hostname", "Vendor", "Operating System", "TTL"])
                
                for device in self.filtered_devices:
                    writer.writerow([
                        device.ip or "Unknown",
                        device.mac,
                        device.hostname or "--",
                        device.vendor,
                        device.os_guess,
                        str(device.ttl) if device.ttl else "--",
                    ])
            
            messagebox.showinfo("Export Successful", f"Exported {len(self.filtered_devices)} device(s) to {filename}")
        except Exception as exc:
            messagebox.showerror("Export Failed", f"Failed to export data: {exc}")

    def _queue_fingerprint(self, device: NetworkDevice) -> None:
        """Schedule a device for background OS fingerprinting."""

        with self._fingerprint_lock:
            if device.mac in self.pending_fingerprint:
                return
            self.pending_fingerprint.add(device.mac)
        self.fingerprint_queue.put((device.mac, device.ip))

    def _schedule_ip_resolution(self) -> None:
        """Periodically check for devices with unknown IPs and try to resolve them from ARP cache."""
        
        def check_and_resolve():
            """Background task to check ARP cache for unknown IPs."""
            try:
                unknown_devices = [
                    device for device in self.devices_by_mac.values()
                    if not device.ip or device.ip == "0.0.0.0"
                ]
                
                # Process up to 10 devices at a time to avoid overhead
                for device in unknown_devices[:10]:
                    ip = get_ip_from_arp_cache(device.mac)
                    if ip and ip != "0.0.0.0":
                        self.event_queue.put((self.EVENT_IP_FOUND, {"mac": device.mac, "ip": ip}))
            except Exception as exc:
                LOGGER.debug("IP resolution check failed: %s", exc)
        
        # Run check in background thread
        threading.Thread(target=check_and_resolve, daemon=True).start()
        
        # Schedule next check in 5 seconds
        self.root.after(5000, self._schedule_ip_resolution)

    def _queue_ip_lookup(self, mac: str) -> None:
        """Schedule a background IP lookup for a MAC address.

        Only checks ARP cache - does NOT trigger network scans to avoid
        creating too many threads that freeze the UI.
        """

        normalized = normalize_mac(mac)
        
        # Avoid duplicate lookups
        with self._fingerprint_lock:
            if normalized in self.pending_ip_lookup:
                return
            self.pending_ip_lookup.add(normalized)
        
        # Quick check of ARP cache only
        ip = get_ip_from_arp_cache(normalized)
        if ip:
            self.event_queue.put((self.EVENT_IP_FOUND, {"mac": normalized, "ip": ip}))
        
        # Clean up tracking
        with self._fingerprint_lock:
            self.pending_ip_lookup.discard(normalized)

    def _fingerprint_worker(self) -> None:
        """Process queued fingerprint jobs using fast TCP SYN probes.
        
        Uses very short timeouts to avoid blocking and keep UI responsive.
        """

        while True:
            job = self.fingerprint_queue.get()
            if job is None:
                break

            mac_address, ip_address = job

            try:
                if not ip_address or ip_address == "0.0.0.0":
                    continue

                # Use only TCP port 80 with very short timeout for speed
                ttl = tcp_syn_probe(ip_address, port=80, timeout=0.3)
                
                # Quick fallback to port 443 if 80 fails
                if ttl is None:
                    ttl = tcp_syn_probe(ip_address, port=443, timeout=0.3)

                if ttl is not None:
                    os_guess = guess_os_from_ttl(ttl)
                    LOGGER.debug("OS fingerprint: %s TTL=%d -> %s",
                                ip_address, ttl, os_guess)
                    
                    self.event_queue.put(
                        (
                            self.EVENT_FINGERPRINT_RESULT,
                            {
                                "mac": mac_address,
                                "ttl": ttl,
                                "os_guess": os_guess,
                            },
                        )
                    )
            except Exception as exc:
                LOGGER.debug("Fingerprint failed for %s: %s", ip_address, exc)
            finally:
                with self._fingerprint_lock:
                    self.pending_fingerprint.discard(mac_address)
                self.fingerprint_queue.task_done()


def main() -> None:
    """Application entry point."""

    root = tk.Tk()
    root.withdraw()
    ensure_admin_privileges(root)
    app = NetOwlApp(root)
    root.deiconify()
    root.mainloop()


if __name__ == "__main__":
    main()