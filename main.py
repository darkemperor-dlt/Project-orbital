


import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, ICMP, DNSQR, send, get_if_list, wrpcap, rdpcap
import threading
from datetime import datetime
import binascii
import socket
import re
import sys
import traceback
import os
import json
import html
import time
from cryptography.fernet import Fernet
import base64

class Tooltip:
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tipwindow or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry(f" +{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                      background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

def create_tooltip(widget, text):
    tooltip = Tooltip(widget)
    def enter(event):
        tooltip.showtip(text)
    def leave(event):
        tooltip.hidetip()
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)

class Orbital:

    def __init__(self, root):
        self.root = root
        self.root.title("Orbital")
        self.root.geometry("1600x1000")
        self.root.resizable(True, True)

        self.packets = []
        self.displayed_packets = []
        self.tcp_streams = {}
        self.http_conversations = {}
        self.dns_conversations = {}
        self.extracted_files = []
        self.filter_presets = {}

        # Rate limiting
        self.rate_limit = 1000  # Packets per second
        self.last_rate_check_time = time.time()
        self.packets_in_current_second = 0

        # Encrypted logging
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.encrypted_log_file = "sensitive_packets.log.enc"

        self.packet_stats = {"total": 0, "ip": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "sensitive": 0, "http": 0, "checksum_errors": 0}

        self.current_theme = "dark"
        self.setup_styles()
        self.create_widgets()
        self.check_admin_rights()
        self.load_presets()
        self.log_action(f"Session encryption key (base64): {base64.urlsafe_b64encode(self.encryption_key).decode()}")
        self.log_action(f"Sensitive data will be logged to {self.encrypted_log_file}")

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("default")
        self.set_theme(self.current_theme)

    def set_theme(self, theme):
        self.current_theme = theme
        if theme == "dark":
            colors = {
                "bg": "#0d0d0d",
                "fg": "#ff2d2d",
                "list_bg": "#1a1a1a",
                "list_fg": "#e6e6e6",
                "selected_bg": "#ff2d2d",
                "selected_fg": "#00ffff",
                "button_bg": "#ff2d2d",
                "button_fg": "#ffffff",
                "active_button_bg": "#00ffff",
                "active_button_fg": "#0d0d0d"
            }
        else:
            colors = {
                "bg": "#f0f0f0",
                "fg": "#000000",
                "list_bg": "#ffffff",
                "list_fg": "#000000",
                "selected_bg": "#0078d7",
                "selected_fg": "#ffffff",
                "button_bg": "#0078d7",
                "button_fg": "#ffffff",
                "active_button_bg": "#005a9e",
                "active_button_fg": "#ffffff"
            }

        self.root.configure(bg=colors["bg"])
        self.style.configure("TNotebook", background=colors["bg"], borderwidth=0, tabmargins=0)
        self.style.configure("TNotebook.Tab",
                             background=colors["list_bg"],
                             foreground=colors["fg"],
                             padding=[30, 15],
                             font=("Orbitron", 16, "bold"),
                             bordercolor=colors["fg"],
                             relief="flat")
        self.style.map("TNotebook.Tab",
                       background=[("selected", colors["selected_bg"]), ("active", colors["active_button_bg"])],
                       foreground=[("selected", colors["selected_fg"]), ("active", colors["button_fg"])],
                       expand=[("selected", [0, 0, 0, 2])])
        self.style.configure("TButton",
                             background=colors["button_bg"],
                             foreground=colors["button_fg"],
                             font=("Orbitron", 13, "bold"),
                             borderwidth=0,
                             padding=10,
                             relief="flat")
        self.style.map("TButton",
                       background=[("active", colors["active_button_bg"])],
                       foreground=[("active", colors["active_button_fg"])])
        self.style.configure("TLabel",
                             background=colors["bg"],
                             foreground=colors["fg"],
                             font=("Orbitron", 14))
        
        # Update all widgets with new colors
        for widget in self.root.winfo_children():
            self.update_widget_colors(widget, colors)

    def update_widget_colors(self, widget, colors):
        try:
            widget.configure(bg=colors["bg"], fg=colors["fg"])
        except tk.TclError:
            pass
        if isinstance(widget, (tk.Listbox, tk.Text)):
            widget.configure(bg=colors["list_bg"], fg=colors["list_fg"],
                             selectbackground=colors["selected_bg"], selectforeground=colors["selected_fg"])
        for child in widget.winfo_children():
            self.update_widget_colors(child, colors)

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.set_theme("light")
        else:
            self.set_theme("dark")

    def create_widgets(self):
        # Top frame for controls
        top_frame = tk.Frame(self.root, bg=self.root.cget('bg'))
        top_frame.pack(fill="x", padx=10, pady=5)

        # Interface selection
        interface_frame = tk.Frame(top_frame, bg=self.root.cget('bg'))
        interface_frame.pack(side=tk.LEFT, fill="x", padx=10, pady=5)
        tk.Label(interface_frame, text="Select Interface:", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(interface_frame, textvariable=self.interface_var, font=("Orbitron", 12))
        self.interface_dropdown.pack(side=tk.LEFT, padx=5)
        self.update_interfaces()
        ttk.Button(interface_frame, text="Start Capture", command=self.start_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(interface_frame, text="Save Packets", command=self.save_packets).pack(side=tk.LEFT, padx=5)
        
        # Theme toggle button
        ttk.Button(top_frame, text="Toggle Theme", command=self.toggle_theme).pack(side=tk.RIGHT, padx=10)

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.create_sniffer_tab()
        self.create_decoder_tab()
        self.create_reconstruction_tab()
        self.create_http_tab()
        self.create_dns_tab()
        self.create_files_tab()
        self.create_injector_tab()
        self.create_log_tab()

    def create_sniffer_tab(self):
        tab1 = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab1, text="Packet Sniffer")

        # Main frame with resizable panels
        main_pane = tk.PanedWindow(tab1, orient=tk.VERTICAL, sashrelief=tk.RAISED, bg=self.root.cget('bg'))
        main_pane.pack(fill="both", expand=True)

        # Top pane for packet list
        packet_frame = tk.Frame(main_pane, bg=self.root.cget('bg'))
        self.packet_list = tk.Listbox(packet_frame, font=("JetBrains Mono", 13), height=20)
        self.packet_list.pack(fill="both", expand=True, side=tk.LEFT)
        scrollbar = tk.Scrollbar(packet_frame, orient="vertical", command=self.packet_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.packet_list.config(yscrollcommand=scrollbar.set)
        self.packet_list.bind("<Button-3>", self.popup_menu)
        self.packet_list.bind('<<ListboxSelect>>', self.show_packet_details)
        main_pane.add(packet_frame)

        # Bottom pane for details and hex view
        details_pane = tk.PanedWindow(main_pane, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg=self.root.cget('bg'))
        
        self.packet_details = tk.Text(details_pane, font=("JetBrains Mono", 12), height=10, wrap=tk.WORD)
        details_pane.add(self.packet_details)

        self.hex_view = tk.Text(details_pane, font=("JetBrains Mono", 12), height=10, wrap=tk.WORD)
        details_pane.add(self.hex_view)
        
        main_pane.add(details_pane)

        # Stats label
        self.stats_label = ttk.Label(tab1, text="Total: 0 | IP: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | DNS: 0 | HTTP: 0 | Sensitive: 0 | Checksum Errors: 0", font=("Orbitron", 13))
        self.stats_label.pack(pady=5)
        
        # Filter controls
        filter_frame = tk.Frame(tab1, bg=self.root.cget('bg'))
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(filter_frame, text="Filter:", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_entry = tk.Entry(filter_frame, textvariable=self.filter_var, font=("JetBrains Mono", 12), width=50)
        filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply", command=self.apply_advanced_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear", command=self.clear_filter).pack(side=tk.LEFT, padx=5)

        # Time filter
        tk.Label(filter_frame, text="Start Time (H:M:S):", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.start_time_var = tk.StringVar()
        tk.Entry(filter_frame, textvariable=self.start_time_var, font=("JetBrains Mono", 12), width=10).pack(side=tk.LEFT, padx=5)
        tk.Label(filter_frame, text="End Time (H:M:S):", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.end_time_var = tk.StringVar()
        tk.Entry(filter_frame, textvariable=self.end_time_var, font=("JetBrains Mono", 12), width=10).pack(side=tk.LEFT, padx=5)

        # Filter presets
        preset_frame = tk.Frame(filter_frame, bg=self.root.cget('bg'))
        preset_frame.pack(side=tk.LEFT, padx=10)
        tk.Label(preset_frame, text="Presets:", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.preset_var = tk.StringVar()
        self.preset_dropdown = ttk.Combobox(preset_frame, textvariable=self.preset_var, font=("Orbitron", 12))
        self.preset_dropdown.pack(side=tk.LEFT, padx=5)
        self.preset_dropdown.bind("<<ComboboxSelected>>", self.load_selected_preset)
        ttk.Button(preset_frame, text="Save", command=self.save_preset).pack(side=tk.LEFT, padx=5)
        ttk.Button(preset_frame, text="Delete", command=self.delete_preset).pack(side=tk.LEFT, padx=5)
        
        # One-click protocol filters
        protocol_filter_frame = tk.Frame(tab1, bg=self.root.cget('bg'))
        protocol_filter_frame.pack(fill="x", padx=10, pady=5)
        for protocol in ["TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP"]:
            ttk.Button(protocol_filter_frame, text=protocol, command=lambda p=protocol: self.quick_filter(p.lower())).pack(side=tk.LEFT, padx=5)

    def create_decoder_tab(self):
        tab2 = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab2, text="Decoder")
        self.decoder_output = tk.Text(tab2, font=("JetBrains Mono", 12), wrap=tk.WORD)
        self.decoder_output.pack(fill="both", expand=True, padx=10, pady=10)

    def create_reconstruction_tab(self):
        tab = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab, text="Session Reconstruction")
        pane = tk.PanedWindow(tab, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        pane.pack(fill="both", expand=True)
        
        self.stream_list = tk.Listbox(pane, font=("JetBrains Mono", 13), height=15)
        self.stream_list.bind('<<ListboxSelect>>', self.view_stream)
        pane.add(self.stream_list)
        
        self.stream_output = tk.Text(pane, font=("JetBrains Mono", 12), wrap=tk.WORD)
        pane.add(self.stream_output)

    def create_http_tab(self):
        tab = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab, text="HTTP Conversations")
        pane = tk.PanedWindow(tab, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        pane.pack(fill="both", expand=True)
        
        self.http_list = tk.Listbox(pane, font=("JetBrains Mono", 13), height=15)
        self.http_list.bind('<<ListboxSelect>>', self.view_http_conversation)
        pane.add(self.http_list)
        
        self.http_output = tk.Text(pane, font=("JetBrains Mono", 12), wrap=tk.WORD)
        pane.add(self.http_output)

    def create_dns_tab(self):
        tab = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab, text="DNS Conversations")
        pane = tk.PanedWindow(tab, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        pane.pack(fill="both", expand=True)
        
        self.dns_list = tk.Listbox(pane, font=("JetBrains Mono", 13), height=15)
        self.dns_list.bind('<<ListboxSelect>>', self.view_dns_conversation)
        pane.add(self.dns_list)
        
        self.dns_output = tk.Text(pane, font=("JetBrains Mono", 12), wrap=tk.WORD)
        pane.add(self.dns_output)

    def create_files_tab(self):
        tab = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab, text="Extracted Files")
        self.file_list = tk.Listbox(tab, font=("JetBrains Mono", 13), height=15)
        self.file_list.pack(fill="both", expand=True, padx=10, pady=10)
        self.file_list.bind("<Double-Button-1>", self.save_extracted_file)

    def create_injector_tab(self):
        tab = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab, text="Injector")
        
        injector_frame = tk.Frame(tab, bg=self.root.cget('bg'))
        injector_frame.pack(padx=10, pady=10, fill='x')
        
        tk.Label(injector_frame, text="Destination IP:", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.dst_ip_entry = tk.Entry(injector_frame, font=("JetBrains Mono", 12), width=20)
        self.dst_ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(injector_frame, text="Payload:", font=("Orbitron", 12)).pack(side=tk.LEFT, padx=5)
        self.payload_entry = tk.Entry(injector_frame, font=("JetBrains Mono", 12), width=40)
        self.payload_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(injector_frame, text="Inject Payload", command=self.inject_payload).pack(side=tk.LEFT, padx=10)

    def create_log_tab(self):
        tab = tk.Frame(self.notebook, bg=self.root.cget('bg'))
        self.notebook.add(tab, text="Action Log")
        self.action_log = tk.Text(tab, font=("JetBrains Mono", 13), wrap=tk.WORD)
        self.action_log.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_action("Orbital Initialized")

    def log_action(self, action):
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        self.action_log.insert(tk.END, f"[{timestamp}] {action}\n")
        self.action_log.yview_moveto(1.0)

    def update_interfaces(self):
        interfaces = get_if_list()
        self.interface_dropdown['values'] = interfaces
        if interfaces:
            self.interface_dropdown.set(interfaces[0])
        self.log_action(f"Available interfaces: {', '.join(interfaces)}")

    def start_capture(self):
        selected_interface = self.interface_var.get()
        if not selected_interface:
            messagebox.showerror("Error", "Please select a network interface!")
            return
        
        self.log_action(f"Starting capture on interface: {selected_interface}")
        self.reset_capture()
        
        sniff_thread = threading.Thread(target=self.sniff_packets, args=(selected_interface,), daemon=True)
        sniff_thread.start()

    def reset_capture(self):
        self.packets.clear()
        self.displayed_packets.clear()
        self.tcp_streams.clear()
        self.http_conversations.clear()
        self.dns_conversations.clear()
        self.extracted_files.clear()
        
        self.packet_list.delete(0, tk.END)
        self.stream_list.delete(0, tk.END)
        self.http_list.delete(0, tk.END)
        self.dns_list.delete(0, tk.END)
        self.file_list.delete(0, tk.END)
        
        for stat in self.packet_stats:
            self.packet_stats[stat] = 0
        self.update_stats()

    def sniff_packets(self, interface):
        sniff(iface=interface, prn=self.packet_handler, store=0, filter=self.filter_var.get())

    def packet_handler(self, packet):
        current_time = time.time()
        if current_time - self.last_rate_check_time >= 1.0:
            self.last_rate_check_time = current_time
            self.packets_in_current_second = 0
        
        if self.packets_in_current_second >= self.rate_limit:
            self.log_action(f"Rate limit exceeded. Dropping packet: {packet.summary()}")
            return

        self.packets_in_current_second += 1

        if not self.validate_checksums(packet):
            self.packet_stats["checksum_errors"] += 1

        if len(self.packets) >= self.MAX_PACKETS:
            self.packets.pop(0)
        self.packets.append(packet)

        self.process_tcp_stream(packet)
        self.process_http(packet)
        self.process_dns(packet)
        self.extract_files(packet)

        if self.is_sensitive(packet):
            self.log_sensitive_packet(packet)

        self.update_ui(packet)

    def validate_checksums(self, packet):
        is_valid = True
        try:
            if IP in packet:
                original_checksum = packet[IP].chksum
                del packet[IP].chksum
                recalculated_packet = IP(bytes(packet[IP]))
                if original_checksum != recalculated_packet.chksum:
                    self.log_action(f"Invalid IP checksum for {packet.summary()}")
                    is_valid = False
                packet[IP].chksum = original_checksum

            if TCP in packet:
                original_checksum = packet[TCP].chksum
                del packet[TCP].chksum
                recalculated_packet = IP(bytes(packet[IP]))
                if original_checksum != recalculated_packet[TCP].chksum:
                    self.log_action(f"Invalid TCP checksum for {packet.summary()}")
                    is_valid = False
                packet[TCP].chksum = original_checksum

            if UDP in packet:
                original_checksum = packet[UDP].chksum
                del packet[UDP].chksum
                recalculated_packet = IP(bytes(packet[IP]))
                if original_checksum != recalculated_packet[UDP].chksum:
                     self.log_action(f"Invalid UDP checksum for {packet.summary()}")
                     is_valid = False
                packet[UDP].chksum = original_checksum
        except Exception as e:
            self.log_action(f"Checksum validation error: {e}")
            is_valid = False
        
        packet._checksum_valid = is_valid
        return is_valid

    def log_sensitive_packet(self, packet):
        try:
            packet_summary = packet.summary()
            raw_data = bytes(packet)
            
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "summary": packet_summary,
                "raw_packet_hex": raw_data.hex()
            }
            
            encrypted_data = self.fernet.encrypt(json.dumps(log_entry).encode())
            
            with open(self.encrypted_log_file, "ab") as f:
                f.write(encrypted_data + b'\n')
            
            self.log_action(f"Logged sensitive packet: {packet_summary}")
        except Exception as e:
            self.log_action(f"Failed to log sensitive packet: {e}")

    def update_ui(self, packet):
       if self.root.winfo_exists():
           self.root.after(0, self._real_update_ui, packet)

    def _real_update_ui(self, packet):
       self.packet_stats["total"] += 1
       self.update_packet_list(packet)
       self.update_stats()

    def update_packet_list(self, packet):
        timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]
        summary = f"[{timestamp}] {packet.summary()}"
        
        self.packet_list.insert(tk.END, summary)
        self.packet_list.yview_moveto(1.0)
        
        color = self.get_packet_color(packet)
        self.packet_list.itemconfig(tk.END, {'fg': color})

    def get_packet_color(self, packet):
        if hasattr(packet, '_checksum_valid') and not packet._checksum_valid:
            return "purple"
        if self.is_sensitive(packet): return "red"
        if DNS in packet: 
            self.packet_stats["dns"] += 1
            return "yellow"
        if TCP in packet:
            if packet.haslayer(Raw) and (b"HTTP" in bytes(packet[Raw])):
                self.packet_stats["http"] += 1
                return "orange"
            self.packet_stats["tcp"] += 1
            return "green"
        if UDP in packet: 
            self.packet_stats["udp"] += 1
            return "cyan"
        if ICMP in packet: 
            self.packet_stats["icmp"] += 1
            return "magenta"
        if IP in packet:
            self.packet_stats["ip"] += 1
        return "white" if self.current_theme == "dark" else "black"

    def show_packet_details(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        
        idx = selection[0]
        packet = self.packets[idx]

        # Show details in decoder tab
        self.decoder_output.delete(1.0, tk.END)
        self.decoder_output.insert(tk.END, packet.show(dump=True))

        # Show details in sniffer tab
        self.packet_details.delete(1.0, tk.END)
        self.packet_details.insert(tk.END, packet.show(dump=True))
        
        # Show hex view
        self.hex_view.delete(1.0, tk.END)
        self.hex_view.insert(tk.END, self.show_hex(packet))

    def show_hex(self, packet):
       raw = bytes(packet)
       hex_data = binascii.hexlify(raw).decode('ascii', errors='replace')[:2048]
       return hex_data

    def process_tcp_stream(self, packet):
        if TCP in packet:
            key = tuple(sorted(((packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport))))
            if key not in self.tcp_streams:
                self.tcp_streams[key] = []
                self.stream_list.insert(tk.END, f"{packet[IP].src}:{packet[TCP].sport} <-> {packet[IP].dst}:{packet[TCP].dport}")
            self.tcp_streams[key].append(packet)

    def view_stream(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        
        selected_item = event.widget.get(selection[0])
        src_str, dst_str = selected_item.split(' <-> ')
        src_ip, src_port = src_str.split(':')
        dst_ip, dst_port = dst_str.split(':')
        key = tuple(sorted(((src_ip, int(src_port)), (dst_ip, int(dst_port)))))

        stream = self.tcp_streams.get(key, [])
        
        self.stream_output.delete(1.0, tk.END)
        reassembled_payload = b""
        for pkt in sorted(stream, key=lambda p: p[TCP].seq):
            if Raw in pkt:
                reassembled_payload += bytes(pkt[Raw])
        
        self.stream_output.insert(tk.END, html.escape(reassembled_payload.decode('ascii', errors='replace')))

    def process_http(self, packet):
        if TCP in packet and Raw in packet and (packet[TCP].sport == 80 or packet[TCP].dport == 80 or packet[TCP].sport == 443 or packet[TCP].dport == 443):
            payload = bytes(packet[Raw])
            if payload.startswith(b"HTTP") or payload.startswith(b"GET") or payload.startswith(b"POST"):
                key = tuple(sorted(((packet[IP].src, packet[TCP].sport), (packet[IP].dst, packet[TCP].dport))))
                if key not in self.http_conversations:
                    self.http_conversations[key] = []
                    self.http_list.insert(tk.END, f"{packet[IP].src}:{packet[TCP].sport} <-> {packet[IP].dst}:{packet[TCP].dport}")
                self.http_conversations[key].append(packet)

    def view_http_conversation(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        
        selected_item = event.widget.get(selection[0])
        src_str, dst_str = selected_item.split(' <-> ')
        src_ip, src_port = src_str.split(':')
        dst_ip, dst_port = dst_str.split(':')
        key = tuple(sorted(((src_ip, int(src_port)), (dst_ip, int(dst_port)))))

        conversation = self.http_conversations.get(key, [])
        
        self.http_output.delete(1.0, tk.END)
        for pkt in conversation:
            self.http_output.insert(tk.END, f"--- {pkt.summary()} ---\n")
            self.http_output.insert(tk.END, self.decode_packet(pkt))
            self.http_output.insert(tk.END, "\n\n")

    def process_dns(self, packet):
        if DNS in packet:
            key = packet[DNS].id
            if key not in self.dns_conversations:
                self.dns_conversations[key] = []
                qname = packet[DNSQR].qname.decode('idna', errors='replace') if DNSQR in packet else "N/A"
                self.dns_list.insert(tk.END, f"ID: {key} | {qname}")
            self.dns_conversations[key].append(packet)

    def view_dns_conversation(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        
        selected_item = event.widget.get(selection[0])
        key = int(selected_item.split(" | ")[0].split(": ")[1])
        conversation = self.dns_conversations.get(key, [])
        
        self.dns_output.delete(1.0, tk.END)
        for pkt in conversation:
            self.dns_output.insert(tk.END, f"--- {pkt.summary()} ---\n")
            self.dns_output.insert(tk.END, pkt.show(dump=True))
            self.dns_output.insert(tk.END, "\n\n")

    def extract_files(self, packet):
        if TCP in packet and Raw in packet:
            payload = bytes(packet[Raw])
            if payload.startswith(b"HTTP"):
                try:
                    headers_end = payload.find(b"\r\n\r\n")
                    if headers_end != -1:
                        headers = payload[:headers_end].decode('ascii', errors='ignore')
                        content_type_match = re.search(r"Content-Type: \w+/([\w.-]+)", headers)
                        if content_type_match:
                            ext = content_type_match.group(1).lower()
                            if ext in self.ALLOWED_EXTENSIONS:
                                filename = f"file_{datetime.now().strftime('%H%M%S')}.{ext}"
                                file_data = payload[headers_end+4:]
                                self.extracted_files.append((filename, file_data))
                                self.file_list.insert(tk.END, filename)
                                self.log_action(f"Extracted file: {filename}")
                            else:
                                self.log_action(f"Blocked file extraction for disallowed extension: {ext}")
                except Exception as e:
                    self.log_action(f"File extraction error: {e}")

    def save_extracted_file(self, event):
        selection = event.widget.curselection()
        if not selection:
            return
        
        filename, file_data = self.extracted_files[selection[0]]
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if save_path:
            with open(save_path, "wb") as f:
                f.write(file_data)
            self.log_action(f"Saved extracted file to {save_path}")

    def update_stats(self):
        self.stats_label.config(text=f"Total: {self.packet_stats['total']} | IP: {self.packet_stats['ip']} | "
                                     f"TCP: {self.packet_stats['tcp']} | UDP: {self.packet_stats['udp']} | "
                                     f"ICMP: {self.packet_stats['icmp']} | DNS: {self.packet_stats['dns']} | "
                                     f"HTTP: {self.packet_stats['http']} | Sensitive: {self.packet_stats['sensitive']} | "
                                     f"Checksum Errors: {self.packet_stats['checksum_errors']}")

    def is_sensitive(self, packet):
        if Raw in packet:
            raw = bytes(packet[Raw]).decode('ascii', errors='ignore').lower()
            patterns = ["password", "user", "login", "key", "token", "credit", "ssn", "api_key", "secret"]
            if any(re.search(p, raw) for p in patterns):
                self.packet_stats["sensitive"] += 1
                return True
        return False

    def redact_sensitive(self, data):
        patterns = ["password", "user", "login", "key", "token", "credit", "ssn", "api_key", "secret"]
        for p in patterns:
            data = re.sub(f"{p}[=:]\\s*\\S+", f"{p}=[REDACTED]", data, flags=re.IGNORECASE)
        return data

    def popup_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Export Packet", command=self.export_packet)
        menu.add_command(label="Replay Packet", command=self.replay_packet)
        menu.add_separator()
        menu.add_command(label="Filter by Source IP", command=self.filter_by_src)
        menu.add_command(label="Filter by Destination IP", command=self.filter_by_dst)
        menu.post(event.x_root, event.y_root)

    def export_packet(self):
        idx = self.packet_list.curselection()
        if not idx: return
        packet = self.packets[idx[0]]
        
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("PCAP files", "*.pcap")])
        if not filename: return

        if filename.endswith(".pcap"):
            wrpcap(filename, packet)
            self.log_action(f"Exported packet to {filename}")
        else:
            with open(filename, "w") as f:
                original_stdout = sys.stdout
                sys.stdout = f
                print(self.redact_sensitive(packet.show(dump=True)))
                sys.stdout = original_stdout
            self.log_action(f"Exported and redacted packet to {filename}")

    def replay_packet(self):
        idx = self.packet_list.curselection()
        if not idx: return
        packet = self.packets[idx[0]]
        send(packet, verbose=0)
        self.log_action(f"Replayed packet: {packet.summary()}")

    def filter_by_src(self):
        idx = self.packet_list.curselection()
        if not idx: return
        packet = self.packets[idx[0]]
        if IP in packet:
            self.filter_var.set(f"src host {packet[IP].src}")
            self.apply_advanced_filter()

    def filter_by_dst(self):
        idx = self.packet_list.curselection()
        if not idx: return
        packet = self.packets[idx[0]]
        if IP in packet:
            self.filter_var.set(f"dst host {packet[IP].dst}")
            self.apply_advanced_filter()

    def apply_advanced_filter(self):
        filter_str = self.filter_var.get()
        start_time_str = self.start_time_var.get()
        end_time_str = self.end_time_var.get()
        
        self.packet_list.delete(0, tk.END)
        
        for packet in self.packets:
            try:
                # Time filter
                if start_time_str:
                    start_time = datetime.strptime(start_time_str, "%H:%M:%S").time()
                    if datetime.fromtimestamp(packet.time).time() < start_time:
                        continue
                if end_time_str:
                    end_time = datetime.strptime(end_time_str, "%H:%M:%S").time()
                    if datetime.fromtimestamp(packet.time).time() > end_time:
                        continue

                # BPF filter
                if filter_str and not self.bpf_filter(packet, filter_str):
                    continue
                    
                self.update_packet_list(packet)
            except Exception as e:
                self.log_action(f"Filter error: {e}")
                self.update_packet_list(packet) # Show packet if filter fails

    def bpf_filter(self, packet, filter_str):
        # This is a simplified BPF filter implementation
        # For a full implementation, a proper BPF engine would be needed
        try:
            # Use Scapy's L2socket to check if the packet matches the filter.
            # This is a workaround to avoid having to re-implement the BPF filter logic.
            from scapy.arch import L2socket
            s = L2socket(filter=filter_str)
            return s.match(packet)
        except Exception as e:
            self.log_action(f"BPF filter error: {e}")
            # Fallback to basic string matching if the BPF filter fails
            filter_str = filter_str.lower()
            if "host" in filter_str:
                ip = filter_str.split("host")[1].strip()
                return IP in packet and (packet[IP].src == ip or packet[IP].dst == ip)
            if "src host" in filter_str:
                ip = filter_str.split("src host")[1].strip()
                return IP in packet and packet[IP].src == ip
            if "dst host" in filter_str:
                ip = filter_str.split("dst host")[1].strip()
                return IP in packet and packet[IP].dst == ip
            if "port" in filter_str:
                port = int(filter_str.split("port")[1].strip())
                return (TCP in packet and (packet[TCP].sport == port or packet[TCP].dport == port)) or \
                       (UDP in packet and (packet[UDP].sport == port or packet[UDP].dport == port))
            if filter_str in str(packet.summary()).lower():
                return True
            return False

    def clear_filter(self):
        self.filter_var.set("")
        self.start_time_var.set("")
        self.end_time_var.set("")
        self.packet_list.delete(0, tk.END)
        for packet in self.packets:
            self.update_packet_list(packet)

    def quick_filter(self, protocol):
        self.filter_var.set(protocol)
        self.apply_advanced_filter()

    def save_preset(self):
        preset_name = simpledialog.askstring("Save Preset", "Enter preset name:")
        if preset_name:
            self.filter_presets[preset_name] = self.filter_var.get()
            self.update_preset_dropdown()
            self.save_presets_to_file()

    def delete_preset(self):
        preset_name = self.preset_var.get()
        if preset_name and messagebox.askyesno("Delete Preset", f"Delete preset '{preset_name}'?"):
            del self.filter_presets[preset_name]
            self.preset_var.set("")
            self.update_preset_dropdown()
            self.save_presets_to_file()

    def load_selected_preset(self, event):
        self.filter_var.set(self.filter_presets.get(self.preset_var.get(), ""))

    def update_preset_dropdown(self):
        self.preset_dropdown['values'] = list(self.filter_presets.keys())

    def save_presets_to_file(self):
        with open("filter_presets.json", "w") as f:
            json.dump(self.filter_presets, f)

    def load_presets(self):
        try:
            with open("filter_presets.json", "r") as f:
                self.filter_presets = json.load(f)
            self.update_preset_dropdown()
        except FileNotFoundError:
            pass

    def check_admin_rights(self):
        import os
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
        else:  # Linux/Mac
            is_admin = (os.getuid() == 0)
        
        if not is_admin:
            messagebox.showwarning(
                "Permission Required", 
                "Run as Administrator/sudo for full capture capabilities."
            )
        return is_admin

    def decode_packet(self, packet):
        try:
            raw_data = bytes(packet[Raw]).decode('ascii', errors='replace') if Raw in packet else ""
            return html.escape(raw_data)
        except Exception as e:
            self.log_action(f"Decode Error: {str(e)}")
            return "[Malformed Packet]"

    def save_packets(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.* ")],
                initialdir=os.getcwd()
            )
            if not filename:
                return
            if not filename.endswith('.pcap'):
                filename += '.pcap'
            wrpcap(filename, self.packets)
        except Exception as e:
            self.log_action(f"Save Failed: {str(e)}")
            messagebox.showerror("Error", f"Secure save failed: {str(e)}")

    def inject_payload(self):
        dst_ip = self.dst_ip_entry.get()
        payload = self.payload_entry.get()

        # Input Validation
        try:
            socket.inet_aton(dst_ip)
        except socket.error:
            messagebox.showerror("Error", "Invalid destination IP address.")
            return
            
        if not payload:
            messagebox.showerror("Error", "Payload cannot be empty.")
            return
            
        if len(payload) > 1400: # Basic MTU check
            messagebox.showwarning("Warning", "Payload is very large and may be fragmented or dropped.")

        try:
            packet = IP(dst=dst_ip)/ICMP()/payload
            send(packet, verbose=0)
            self.log_action(f"Injected payload to {dst_ip}: {payload}")
        except Exception as e:
            self.log_action(f"Injection failed: {e}")
            messagebox.showerror("Error", f"Failed to inject packet: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = Orbital(root)
    root.mainloop()