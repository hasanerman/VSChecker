import os
import sys
import hashlib
import subprocess
import threading
import time
import re
import json
import sqlite3
import shutil
import math
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
from pathlib import Path
import psutil

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class VirusEngine:
    def __init__(self):
        self.malware_hashes = {
            "5d41402abc4b2a76b9719d911017c592": "Test Malware 1",
            "098f6bcd4621d373cade4e832627b4f6": "Test Malware 2",
            "e3b0c44298fc1c149afbf4c8996fb924": "Empty File Dropper",
            "d41d8cd98f00b204e9800998ecf8427e": "Zero Byte Malware"
        }
        self.dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', 
            '.js', '.jar', '.msi', '.dll', '.sys', '.ocx', '.cpl',
            '.app', '.deb', '.rpm', '.dmg', '.pkg'
        ]
        self.malware_names = [
            'virus', 'trojan', 'backdoor', 'keylogger', 'spyware',
            'adware', 'rootkit', 'worm', 'ransomware', 'cryptolocker',
            'miner', 'botnet', 'stealer', 'rat', 'payload'
        ]
        self.suspicious_processes = [
            'bitcoin', 'crypto', 'miner', 'keylog', 'backdoor',
            'trojan', 'virus', 'malware', 'hack', 'crack'
        ]
        self.scan_count = 0
        self.threat_count = 0

    def calculate_hash(self, filepath):
        try:
            hasher = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def calculate_entropy(self, filepath):
        try:
            if not os.path.exists(filepath):
                return 0.0
            counter = Counter()
            length = 0
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    counter.update(chunk)
                    length += len(chunk)
                    if length > 5 * 1024 * 1024:
                        break
            if length == 0:
                return 0.0
            entropy = 0.0
            for count in counter.values():
                p = count / length
                entropy -= p * math.log2(p)
            return entropy
        except:
            return 0.0

    def scan_file(self, filepath):
        self.scan_count += 1
        if not os.path.exists(filepath):
            return self.create_result(filepath, False, "File not found")
        if not os.access(filepath, os.R_OK):
            return self.create_result(filepath, False, "Access denied (No read permission)")
        filename = os.path.basename(filepath).lower()
        file_ext = os.path.splitext(filename)[1].lower()
        file_size = 0
        try:
            file_size = os.path.getsize(filepath)
        except:
            pass
        file_hash = self.calculate_hash(filepath)
        if file_hash and file_hash in self.malware_hashes:
            self.threat_count += 1
            return self.create_result(filepath, True, f"Known malware: {self.malware_hashes[file_hash]}", file_hash, file_size)
        for malware_name in self.malware_names:
            if malware_name in filename:
                self.threat_count += 1
                return self.create_result(filepath, True, f"Suspicious filename: {malware_name}", file_hash, file_size)
        if file_ext in self.dangerous_extensions:
            if file_ext == '.exe' and file_size < 2048:
                self.threat_count += 1
                return self.create_result(filepath, True, "Suspicious exe file (too small)", file_hash, file_size)
            if file_ext in ['.bat', '.cmd', '.vbs'] and file_size > 1024 * 1024:
                self.threat_count += 1
                return self.create_result(filepath, True, f"Suspicious {file_ext} file (too large)", file_hash, file_size)
        if filename.count('.') > 2:
            self.threat_count += 1
            return self.create_result(filepath, True, "Suspicious double extension", file_hash, file_size)
        if filename.startswith('.') and file_ext in self.dangerous_extensions:
            self.threat_count += 1
            return self.create_result(filepath, True, "Hidden malicious file", file_hash, file_size)
        entropy = self.calculate_entropy(filepath)
        if file_ext in ['.exe', '.dll', '.sys', '.scr', '.com', '.pif'] and entropy > 7.5:
            self.threat_count += 1
            return self.create_result(filepath, True, f"Suspicious file (High entropy: {entropy:.2f})", file_hash, file_size)
        try:
            if file_ext in ['.txt', '.log'] and file_size > 0:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024).lower()
                    if any(keyword in content for keyword in ['password', 'credit card', 'ssn', 'social security']):
                        self.threat_count += 1
                        return self.create_result(filepath, True, "Suspicious content detected", file_hash, file_size)
        except:
            pass
        return self.create_result(filepath, False, "Clean", file_hash, file_size)

    def create_result(self, filepath, is_threat, reason, file_hash=None, file_size=0):
        return {
            'path': filepath,
            'is_threat': is_threat,
            'reason': reason,
            'hash': file_hash,
            'size': file_size,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def scan_processes(self):
        threats = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                if not info['name']:
                    continue
                name_lower = info['name'].lower()
                for suspicious in self.suspicious_processes:
                    if suspicious in name_lower:
                        threats.append({
                            'pid': info['pid'],
                            'name': info['name'],
                            'path': info['exe'] or 'Unknown',
                            'cpu': info['cpu_percent'] or 0,
                            'memory': info['memory_percent'] or 0,
                            'reason': f'Suspicious process name: {suspicious}'
                        })
                        continue
                if info['cpu_percent'] and info['cpu_percent'] > 90:
                    threats.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'path': info['exe'] or 'Unknown',
                        'cpu': info['cpu_percent'],
                        'memory': info['memory_percent'] or 0,
                        'reason': f'High CPU usage: %{info["cpu_percent"]:.1f}'
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return threats

class QuarantineManager:
    def __init__(self):
        self.quarantine_dir = os.path.join(os.path.expanduser("~"), "VSChecker", "Quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine_file(self, filepath):
        try:
            if not os.path.exists(filepath):
                return False, "File not found"
            filename = os.path.basename(filepath)
            timestamp = int(time.time())
            quarantine_name = f"{timestamp}_{filename}.quarantined"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            shutil.move(filepath, quarantine_path)
            info_file = quarantine_path + ".info"
            with open(info_file, 'w') as f:
                json.dump({
                    'original_path': filepath,
                    'quarantine_time': datetime.now().isoformat(),
                    'quarantine_path': quarantine_path
                }, f, indent=2)
            return True, quarantine_path
        except Exception as e:
            return False, str(e)

    def restore_file(self, quarantine_path):
        try:
            info_file = quarantine_path + ".info"
            if not os.path.exists(info_file):
                return False, "Info file not found"
            with open(info_file, 'r') as f:
                info = json.load(f)
            original_path = info['original_path']
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(quarantine_path, original_path)
            os.remove(info_file)
            return True, original_path
        except Exception as e:
            return False, str(e)

class DatabaseManager:
    def __init__(self):
        self.db_path = os.path.join(os.path.expanduser("~"), "VSChecker", "database.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_database()

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                is_threat INTEGER,
                threat_type TEXT,
                file_hash TEXT,
                file_size INTEGER,
                action_taken TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                original_path TEXT,
                quarantine_path TEXT,
                status TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def save_scan_result(self, result, action="scanned"):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history 
            (timestamp, file_path, is_threat, threat_type, file_hash, file_size, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            result['timestamp'],
            result['path'],
            1 if result['is_threat'] else 0,
            result['reason'],
            result['hash'],
            result['size'],
            action
        ))
        conn.commit()
        conn.close()

    def update_scan_action(self, file_path, action):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scan_history 
                SET action_taken = ? 
                WHERE file_path = ? AND id = (
                    SELECT id FROM scan_history 
                    WHERE file_path = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                )
            ''', (action, file_path, file_path))
            conn.commit()
            conn.close()
        except:
            pass

    def get_scan_history(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM scan_history 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        results = cursor.fetchall()
        conn.close()
        return results

    def get_statistics(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        stats = {}
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        stats['total_scans'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE is_threat = 1")
        stats['threats_found'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE is_threat = 0")
        stats['clean_files'] = cursor.fetchone()[0]
        cursor.execute("SELECT MAX(timestamp) FROM scan_history")
        stats['last_scan'] = cursor.fetchone()[0] or "No scans performed yet"
        conn.close()
        return stats

class AntivirusGUI:
    def __init__(self):
        self.engine = VirusEngine()
        self.quarantine = QuarantineManager()
        self.database = DatabaseManager()
        self.scanning = False
        self.scan_thread = None
        self.config = self.load_config()
        self.root = ctk.CTk()
        self.root.title("VSChecker")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        self.setup_gui()

    def load_config(self):
        config_path = os.path.join(os.path.expanduser("~"), "VSChecker", "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def save_config(self):
        config_path = os.path.join(os.path.expanduser("~"), "VSChecker", "config.json")
        config = {
            "vt_api_key": self.vt_entry.get().strip()
        }
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except:
            pass

    def change_appearance_mode(self, mode):
        ctk.set_appearance_mode(mode.lower())

    def set_buttons_state(self, state):
        self.scan_file_btn.configure(state=state)
        self.scan_folder_btn.configure(state=state)
        self.quick_scan_btn.configure(state=state)
        self.full_scan_btn.configure(state=state)
        self.process_scan_btn.configure(state=state)

    def setup_gui(self):
        title_frame = ctk.CTkFrame(self.root)
        title_frame.pack(fill="x", padx=10, pady=5)
        title_label = ctk.CTkLabel(
            title_frame, 
            text="VSChecker", 
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(pady=10)
        control_frame = ctk.CTkFrame(self.root)
        control_frame.pack(fill="x", padx=10, pady=5)
        button_frame = ctk.CTkFrame(control_frame)
        button_frame.pack(fill="x", padx=10, pady=10)
        self.scan_file_btn = ctk.CTkButton(
            button_frame, 
            text="Scan File",
            command=self.scan_file,
            width=120,
            height=40
        )
        self.scan_file_btn.pack(side="left", padx=5)
        self.scan_folder_btn = ctk.CTkButton(
            button_frame,
            text="Scan Folder", 
            command=self.scan_folder,
            width=120,
            height=40
        )
        self.scan_folder_btn.pack(side="left", padx=5)
        self.quick_scan_btn = ctk.CTkButton(
            button_frame,
            text="Quick Scan",
            command=self.quick_scan,
            width=120,
            height=40
        )
        self.quick_scan_btn.pack(side="left", padx=5)
        self.full_scan_btn = ctk.CTkButton(
            button_frame,
            text="Full Scan",
            command=self.full_scan,
            width=120,
            height=40
        )
        self.full_scan_btn.pack(side="left", padx=5)
        self.process_scan_btn = ctk.CTkButton(
            button_frame,
            text="Scan Processes",
            command=self.scan_processes,
            width=120,
            height=40
        )
        self.process_scan_btn.pack(side="left", padx=5)
        self.stop_btn = ctk.CTkButton(
            button_frame,
            text="Stop",
            command=self.stop_scan,
            width=100,
            height=40,
            fg_color="red",
            hover_color="darkred"
        )
        self.stop_btn.pack(side="right", padx=5)
        status_frame = ctk.CTkFrame(control_frame)
        status_frame.pack(fill="x", padx=10, pady=(0, 10))
        self.status_label = ctk.CTkLabel(status_frame, text="Ready - Waiting for scan", font=ctk.CTkFont(size=12))
        self.status_label.pack(pady=5)
        self.progress_bar = ctk.CTkProgressBar(status_frame)
        self.progress_bar.pack(fill="x", padx=20, pady=5)
        self.progress_bar.set(0)
        self.notebook = ctk.CTkTabview(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        self.setup_scan_results_tab()
        self.setup_process_tab()
        self.setup_quarantine_tab()
        self.setup_history_tab()
        self.setup_settings_tab()

    def sort_treeview(self, tree, col, reverse):
        l = [(tree.set(k, col), k) for k in tree.get_children("")]
        def parse_value(val):
            cleaned = val.replace(" bytes", "").replace(",", "")
            try:
                return int(cleaned)
            except ValueError:
                try:
                    return float(cleaned.replace("%", ""))
                except ValueError:
                    return val.lower()
        l.sort(key=lambda t: parse_value(t[0]), reverse=reverse)
        for index, (val, k) in enumerate(l):
            tree.move(k, "", index)
        tree.heading(col, command=lambda: self.sort_treeview(tree, col, not reverse))

    def setup_scan_results_tab(self):
        tab = self.notebook.add("Scan Results")
        columns = ("File Path", "Status", "Threat Type", "Size", "Hash")
        self.results_tree = ttk.Treeview(tab, columns=columns, show="headings", height=20)
        self.results_tree.heading("File Path", text="File Path", command=lambda: self.sort_treeview(self.results_tree, "File Path", False))
        self.results_tree.heading("Status", text="Status", command=lambda: self.sort_treeview(self.results_tree, "Status", False))
        self.results_tree.heading("Threat Type", text="Threat Type", command=lambda: self.sort_treeview(self.results_tree, "Threat Type", False))
        self.results_tree.heading("Size", text="Size", command=lambda: self.sort_treeview(self.results_tree, "Size", False))
        self.results_tree.heading("Hash", text="Hash (MD5)", command=lambda: self.sort_treeview(self.results_tree, "Hash", False))
        self.results_tree.column("File Path", width=400)
        self.results_tree.column("Status", width=100)
        self.results_tree.column("Threat Type", width=200)
        self.results_tree.column("Size", width=100)
        self.results_tree.column("Hash", width=150)
        self.results_tree.tag_configure("threat", foreground="red")
        self.results_tree.tag_configure("clean", foreground="green")
        self.results_tree.tag_configure("quarantined", foreground="orange")
        self.results_tree.tag_configure("deleted", foreground="gray")
        scrollbar_results = ttk.Scrollbar(tab, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar_results.set)
        self.results_tree.pack(side="left", fill="both", expand=True)
        scrollbar_results.pack(side="right", fill="y")
        self.results_menu = tk.Menu(self.root, tearoff=0)
        self.results_menu.add_command(label="Quarantine File", command=self.quarantine_selected)
        self.results_menu.add_command(label="Delete File", command=self.delete_selected)
        self.results_menu.add_command(label="Copy Path", command=self.copy_path)
        self.results_menu.add_command(label="Show in Folder", command=self.show_in_folder)
        self.results_menu.add_command(label="VirusTotal Check", command=self.check_virustotal_selected)
        self.results_tree.bind("<Button-3>", self.show_results_menu)

    def setup_process_tab(self):
        tab = self.notebook.add("Suspicious Processes")
        columns = ("PID", "Name", "Path", "CPU %", "RAM %", "Reason")
        self.process_tree = ttk.Treeview(tab, columns=columns, show="headings", height=20)
        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.process_tree, c, False))
            self.process_tree.column(col, width=120)
        scrollbar_process = ttk.Scrollbar(tab, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar_process.set)
        self.process_tree.pack(side="left", fill="both", expand=True)
        scrollbar_process.pack(side="right", fill="y")
        self.process_menu = tk.Menu(self.root, tearoff=0)
        self.process_menu.add_command(label="Kill Process", command=self.kill_process)
        self.process_menu.add_command(label="Show File Location", command=self.show_process_location)
        self.process_tree.bind("<Button-3>", self.show_process_menu)

    def setup_quarantine_tab(self):
        tab = self.notebook.add("Quarantine")
        control_frame = ctk.CTkFrame(tab)
        control_frame.pack(fill="x", padx=5, pady=5)
        refresh_btn = ctk.CTkButton(control_frame, text="Refresh", command=self.refresh_quarantine)
        refresh_btn.pack(side="left", padx=5, pady=5)
        clear_btn = ctk.CTkButton(control_frame, text="Clear All", command=self.clear_quarantine, fg_color="red")
        clear_btn.pack(side="left", padx=5, pady=5)
        columns = ("File", "Quarantine Date", "Original Path")
        self.quarantine_tree = ttk.Treeview(tab, columns=columns, show="headings", height=15)
        for col in columns:
            self.quarantine_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.quarantine_tree, c, False))
            self.quarantine_tree.column(col, width=200)
        scrollbar_quar = ttk.Scrollbar(tab, orient="vertical", command=self.quarantine_tree.yview)
        self.quarantine_tree.configure(yscrollcommand=scrollbar_quar.set)
        self.quarantine_tree.pack(side="left", fill="both", expand=True, padx=(5, 0))
        scrollbar_quar.pack(side="right", fill="y", padx=(0, 5))
        self.quarantine_menu = tk.Menu(self.root, tearoff=0)
        self.quarantine_menu.add_command(label="Restore File", command=self.restore_quarantine)
        self.quarantine_menu.add_command(label="Permanently Delete", command=self.delete_quarantine)
        self.quarantine_tree.bind("<Button-3>", self.show_quarantine_menu)

    def setup_history_tab(self):
        tab = self.notebook.add("Scan History")
        control_frame = ctk.CTkFrame(tab)
        control_frame.pack(fill="x", padx=5, pady=5)
        refresh_history_btn = ctk.CTkButton(control_frame, text="Refresh History", command=self.refresh_history)
        refresh_history_btn.pack(side="left", padx=5, pady=5)
        clear_history_btn = ctk.CTkButton(control_frame, text="Clear History", command=self.clear_history, fg_color="orange")
        clear_history_btn.pack(side="left", padx=5, pady=5)
        columns = ("Date", "File", "Status", "Threat", "Action")
        self.history_tree = ttk.Treeview(tab, columns=columns, show="headings", height=15)
        for col in columns:
            self.history_tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(self.history_tree, c, False))
            self.history_tree.column(col, width=150)
        scrollbar_hist = ttk.Scrollbar(tab, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar_hist.set)
        self.history_tree.pack(side="left", fill="both", expand=True, padx=(5, 0))
        scrollbar_hist.pack(side="right", fill="y", padx=(0, 5))

    def setup_settings_tab(self):
        tab = self.notebook.add("Settings & Statistics")
        stats_frame = ctk.CTkFrame(tab)
        stats_frame.pack(fill="x", padx=10, pady=10)
        stats_title = ctk.CTkLabel(stats_frame, text="Statistics", font=ctk.CTkFont(size=18, weight="bold"))
        stats_title.pack(pady=10)
        self.stats_text = ctk.CTkTextbox(stats_frame, height=180)
        self.stats_text.pack(fill="x", padx=10, pady=(0, 10))
        settings_frame = ctk.CTkFrame(tab)
        settings_frame.pack(fill="both", expand=True, padx=10, pady=10)
        settings_title = ctk.CTkLabel(settings_frame, text="Settings", font=ctk.CTkFont(size=18, weight="bold"))
        settings_title.pack(pady=10)
        
        quar_frame = ctk.CTkFrame(settings_frame)
        quar_frame.pack(fill="x", padx=10, pady=5)
        quar_label = ctk.CTkLabel(quar_frame, text="Quarantine Folder:")
        quar_label.pack(side="left", padx=10, pady=5)
        self.quar_path_entry = ctk.CTkEntry(quar_frame, width=300)
        self.quar_path_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.quar_path_entry.insert(0, self.quarantine.quarantine_dir)
        browse_quar_btn = ctk.CTkButton(quar_frame, text="Browse", command=self.browse_quarantine_folder)
        browse_quar_btn.pack(side="right", padx=5)

        theme_frame = ctk.CTkFrame(settings_frame)
        theme_frame.pack(fill="x", padx=10, pady=5)
        theme_label = ctk.CTkLabel(theme_frame, text="Appearance Mode:")
        theme_label.pack(side="left", padx=10, pady=5)
        self.theme_menu = ctk.CTkOptionMenu(
            theme_frame,
            values=["Dark", "Light", "System"],
            command=self.change_appearance_mode
        )
        self.theme_menu.pack(side="right", padx=10, pady=5)
        self.theme_menu.set("Dark")

        vt_frame = ctk.CTkFrame(settings_frame)
        vt_frame.pack(fill="x", padx=10, pady=5)
        vt_label = ctk.CTkLabel(vt_frame, text="VirusTotal API Key:")
        vt_label.pack(side="left", padx=10, pady=5)
        self.vt_entry = ctk.CTkEntry(vt_frame, width=300, show="*")
        self.vt_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.vt_entry.insert(0, self.config.get("vt_api_key", ""))

        system_frame = ctk.CTkFrame(tab)
        system_frame.pack(fill="both", expand=True, padx=10, pady=10)
        system_title = ctk.CTkLabel(system_frame, text="System Status", font=ctk.CTkFont(size=16, weight="bold"))
        system_title.pack(pady=5)
        self.system_text = ctk.CTkTextbox(system_frame, height=150)
        self.system_text.pack(fill="both", expand=True, padx=10, pady=5)
        self.update_stats()
        self.update_system_info()

    def scan_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.start_scan([file_path], "File Scan")

    def scan_folder(self):
        folder_path = filedialog.askdirectory(title="Select folder to scan")
        if folder_path:
            self.start_scan_folder(folder_path, "Folder Scan")

    def quick_scan(self):
        quick_paths = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            "C:\\Windows\\System32\\drivers",
            "C:\\Windows\\Temp",
            "C:\\Temp"
        ]
        existing_paths = [path for path in quick_paths if os.path.exists(path)]
        if existing_paths:
            self.start_scan_folder(existing_paths, "Quick Scan")

    def full_scan(self):
        if messagebox.askyesno("Full Scan", "Full system scan may take a long time. Do you want to continue?"):
            full_paths = [
                "C:\\",
                os.path.expanduser("~")
            ]
            self.start_scan_folder(full_paths, "Full Scan")

    def scan_processes(self):
        if self.scanning:
            messagebox.showwarning("Warning", "A scan is already in progress!")
            return
        self.status_label.configure(text="Scanning processes...")
        self.progress_bar.set(0.5)
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        threats = self.engine.scan_processes()
        for threat in threats:
            self.process_tree.insert("", "end", values=(
                threat['pid'],
                threat['name'],
                threat['path'],
                f"{threat['cpu']:.1f}%",
                f"{threat['memory']:.1f}%",
                threat['reason']
            ))
        self.progress_bar.set(1.0)
        self.status_label.configure(text=f"Process scan completed - {len(threats)} suspicious processes found")
        self.notebook.set("Suspicious Processes")

    def start_scan(self, file_paths, scan_type):
        if self.scanning:
            messagebox.showwarning("Warning", "A scan is already in progress!")
            return
        self.scanning = True
        self.set_buttons_state("disabled")
        self.clear_results()
        self.scan_thread = threading.Thread(target=self.scan_files_thread, args=(file_paths, scan_type))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def start_scan_folder(self, folder_paths, scan_type):
        if self.scanning:
            messagebox.showwarning("Warning", "A scan is already in progress!")
            return
        self.scanning = True
        self.set_buttons_state("disabled")
        self.clear_results()
        self.scan_thread = threading.Thread(target=self.scan_folders_thread, args=(folder_paths, scan_type))
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def scan_files_thread(self, file_paths, scan_type):
        try:
            total_files = len(file_paths)
            for i, file_path in enumerate(file_paths):
                if not self.scanning:
                    break
                self.root.after(0, self.update_status, f"{scan_type} - {os.path.basename(file_path)}")
                self.root.after(0, self.update_progress, (i + 1) / total_files)
                result = self.engine.scan_file(file_path)
                self.root.after(0, self.add_scan_result, result)
                self.database.save_scan_result(result)
                time.sleep(0.1)
            if self.scanning:
                self.root.after(0, self.scan_completed, f"{scan_type} completed")
            else:
                self.root.after(0, self.scan_completed, f"{scan_type} stopped")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Scan error: {str(e)}")
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.set_buttons_state("normal"))

    def scan_folders_thread(self, folder_paths, scan_type):
        try:
            all_files = []
            self.root.after(0, self.update_status, "Listing files...")
            if isinstance(folder_paths, str):
                folder_paths = [folder_paths]
            for folder_path in folder_paths:
                if not self.scanning:
                    break
                if os.path.isfile(folder_path):
                    all_files.append(folder_path)
                elif os.path.isdir(folder_path):
                    for root, dirs, files in os.walk(folder_path):
                        if not self.scanning:
                            break
                        for file in files:
                            all_files.append(os.path.join(root, file))
                            if len(all_files) % 1000 == 0:
                                self.root.after(0, self.update_status, f"Listing files... ({len(all_files)} files found)")
            if not self.scanning:
                self.root.after(0, self.scan_completed, f"{scan_type} stopped")
                return
            total_files = len(all_files)
            self.root.after(0, self.update_status, f"{total_files} files found, starting scan...")
            for i, file_path in enumerate(all_files):
                if not self.scanning:
                    break
                self.root.after(0, self.update_status, f"{scan_type} - {os.path.basename(file_path)} ({i+1}/{total_files})")
                self.root.after(0, self.update_progress, (i + 1) / total_files)
                result = self.engine.scan_file(file_path)
                self.root.after(0, self.add_scan_result, result)
                self.database.save_scan_result(result)
                if i % 10 == 0:
                    time.sleep(0.05)
            if self.scanning:
                self.root.after(0, self.scan_completed, f"{scan_type} completed - {total_files} files scanned")
            else:
                self.root.after(0, self.scan_completed, f"{scan_type} stopped")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"Scan error: {str(e)}")
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.set_buttons_state("normal"))

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.status_label.configure(text="Stopping scan...")

    def update_status(self, message):
        self.status_label.configure(text=message)

    def update_progress(self, value):
        self.progress_bar.set(value)

    def scan_completed(self, message):
        self.status_label.configure(text=message)
        self.progress_bar.set(1.0)
        self.update_stats()
        self.set_buttons_state("normal")
        if self.engine.threat_count > 0:
            messagebox.showwarning("Threat Detected!", 
                f"{self.engine.threat_count} suspicious files detected!\n"
                "Please review the results and take appropriate actions.")

    def clear_results(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.engine.scan_count = 0
        self.engine.threat_count = 0

    def add_scan_result(self, result):
        status = "TEHDIT" if result['is_threat'] else "TEMIZ"
        size_str = f"{result['size']:,} bytes" if result['size'] > 0 else "N/A"
        hash_str = result['hash'][:8] + "..." if result['hash'] else "N/A"
        tag = "threat" if result['is_threat'] else "clean"
        item = self.results_tree.insert("", "end", values=(
            result['path'],
            status,
            result['reason'],
            size_str,
            hash_str
        ), tags=(tag,))

    def show_results_menu(self, event):
        item = self.results_tree.selection()
        if item:
            self.results_menu.post(event.x_root, event.y_root)

    def show_process_menu(self, event):
        item = self.process_tree.selection()
        if item:
            self.process_menu.post(event.x_root, event.y_root)

    def show_quarantine_menu(self, event):
        item = self.quarantine_tree.selection()
        if item:
            self.quarantine_menu.post(event.x_root, event.y_root)

    def quarantine_selected(self):
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file!")
            return
        item = selection[0]
        file_path = self.results_tree.item(item, "values")[0]
        if messagebox.askyesno("Quarantine", f"Do you want to quarantine this file?\n\n{file_path}"):
            success, message = self.quarantine.quarantine_file(file_path)
            if success:
                messagebox.showinfo("Success", f"File quarantined successfully:\n{message}")
                self.results_tree.set(item, "Status", "QUARANTINED")
                self.results_tree.item(item, tags=("quarantined",))
                self.database.update_scan_action(file_path, "Quarantined")
                self.refresh_quarantine()
            else:
                messagebox.showerror("Error", f"Quarantine error:\n{message}")

    def delete_selected(self):
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file!")
            return
        item = selection[0]
        file_path = self.results_tree.item(item, "values")[0]
        if messagebox.askyesno("Delete File", f"Do you want to permanently delete this file?\n\n{file_path}"):
            try:
                os.remove(file_path)
                messagebox.showinfo("Success", "File successfully deleted!")
                self.results_tree.set(item, "Status", "DELETED")
                self.results_tree.item(item, tags=("deleted",))
                self.database.update_scan_action(file_path, "Deleted")
            except Exception as e:
                messagebox.showerror("Error", f"Delete error:\n{str(e)}")

    def copy_path(self):
        selection = self.results_tree.selection()
        if not selection:
            return
        item = selection[0]
        file_path = self.results_tree.item(item, "values")[0]
        self.root.clipboard_clear()
        self.root.clipboard_append(file_path)
        messagebox.showinfo("Success", "File path copied to clipboard!")

    def show_in_folder(self):
        selection = self.results_tree.selection()
        if not selection:
            return
        item = selection[0]
        file_path = self.results_tree.item(item, "values")[0]
        try:
            subprocess.run(['explorer', '/select,', file_path])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open directory:\n{str(e)}")

    def check_virustotal_selected(self):
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file from the list!")
            return
        item = selection[0]
        values = self.results_tree.item(item, "values")
        file_path = values[0]
        file_hash = self.engine.calculate_hash(file_path)
        if not file_hash:
            messagebox.showerror("Error", "Could not calculate file hash!")
            return
        api_key = self.vt_entry.get().strip()
        if not api_key:
            messagebox.showwarning("Warning", "Please enter your VirusTotal API key in Settings & Statistics first!")
            self.notebook.set("Settings & Statistics")
            return
        self.save_config()
        self.status_label.configure(text="Querying VirusTotal...")
        threading.Thread(
            target=self.vt_query_thread,
            args=(file_hash, api_key, item),
            daemon=True
        ).start()

    def vt_query_thread(self, file_hash, api_key, item):
        result_text = self.query_virustotal(file_hash, api_key)
        self.root.after(0, self.show_vt_result, result_text, item)

    def query_virustotal(self, file_hash, api_key):
        if not api_key:
            return "API Key is required"
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", api_key)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                undetected = stats.get("undetected", 0)
                total = sum(stats.values())
                if total > 0:
                    return f"VirusTotal Detection: {malicious}/{total} engines flagged it"
                else:
                    return "No analysis stats found on VirusTotal"
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "File not found on VirusTotal (Unknown hash)"
            elif e.code == 401 or e.code == 403:
                return "Invalid API Key"
            else:
                return f"VirusTotal Error: HTTP {e.code}"
        except Exception as e:
            return f"Connection error: {str(e)}"

    def show_vt_result(self, result_text, item):
        self.status_label.configure(text="VirusTotal check completed")
        messagebox.showinfo("VirusTotal Result", result_text)
        if "flagged" in result_text or "Detection" in result_text:
            try:
                match = re.search(r"Detection: (\d+)/", result_text)
                if match and int(match.group(1)) > 0:
                    self.results_tree.set(item, "Threat Type", result_text)
                    self.results_tree.set(item, "Status", "TEHDIT")
                    self.results_tree.item(item, tags=("threat",))
            except:
                pass

    def kill_process(self):
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a process!")
            return
        item = selection[0]
        values = self.process_tree.item(item, "values")
        pid = int(values[0])
        name = values[1]
        if messagebox.askyesno("Kill Process", f"Do you want to terminate this process?\n\nPID: {pid}\nName: {name}"):
            try:
                process = psutil.Process(pid)
                process.terminate()
                process.wait(timeout=3)
                messagebox.showinfo("Success", "Process successfully terminated!")
                self.process_tree.delete(item)
            except psutil.TimeoutExpired:
                try:
                    process.kill()
                    messagebox.showinfo("Success", "Process forcefully terminated!")
                    self.process_tree.delete(item)
                except Exception as e:
                    messagebox.showerror("Error", f"Process termination error:\n{str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Process termination error:\n{str(e)}")

    def show_process_location(self):
        selection = self.process_tree.selection()
        if not selection:
            return
        item = selection[0]
        values = self.process_tree.item(item, "values")
        process_path = values[2]
        if process_path and process_path != "Unknown":
            try:
                subprocess.run(['explorer', '/select,', process_path])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open directory:\n{str(e)}")
        else:
            messagebox.showwarning("Warning", "Process file location is unknown!")

    def refresh_quarantine(self):
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        try:
            for file in os.listdir(self.quarantine.quarantine_dir):
                if file.endswith('.quarantined'):
                    file_path = os.path.join(self.quarantine.quarantine_dir, file)
                    info_file = file_path + ".info"
                    if os.path.exists(info_file):
                        try:
                            with open(info_file, 'r') as f:
                                info = json.load(f)
                            self.quarantine_tree.insert("", "end", values=(
                                file.replace('.quarantined', ''),
                                info.get('quarantine_time', 'Unknown')[:19],
                                info.get('original_path', 'Unknown')
                            ))
                        except:
                            self.quarantine_tree.insert("", "end", values=(
                                file,
                                "Could not read info",
                                "Unknown"
                            ))
        except Exception as e:
            messagebox.showerror("Error", f"Quarantine list refresh error:\n{str(e)}")

    def clear_quarantine(self):
        if messagebox.askyesno("Clear Quarantine", "Do you want to permanently delete all files in quarantine?"):
            try:
                for file in os.listdir(self.quarantine.quarantine_dir):
                    file_path = os.path.join(self.quarantine.quarantine_dir, file)
                    os.remove(file_path)
                messagebox.showinfo("Success", "Quarantine cleared!")
                self.refresh_quarantine()
            except Exception as e:
                messagebox.showerror("Error", f"Quarantine clearing error:\n{str(e)}")

    def restore_quarantine(self):
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file!")
            return
        item = selection[0]
        values = self.quarantine_tree.item(item, "values")
        filename = values[0] + ".quarantined"
        quarantine_path = os.path.join(self.quarantine.quarantine_dir, filename)
        if messagebox.askyesno("Restore File", f"Do you want to restore this file to its original path?\n\n{values[0]}"):
            success, message = self.quarantine.restore_file(quarantine_path)
            if success:
                messagebox.showinfo("Success", f"File restored successfully:\n{message}")
                self.refresh_quarantine()
            else:
                messagebox.showerror("Error", f"Restore error:\n{message}")

    def delete_quarantine(self):
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file!")
            return
        item = selection[0]
        values = self.quarantine_tree.item(item, "values")
        filename = values[0] + ".quarantined"
        quarantine_path = os.path.join(self.quarantine.quarantine_dir, filename)
        info_path = quarantine_path + ".info"
        if messagebox.askyesno("Permanently Delete", f"Do you want to permanently delete this file?\n\n{values[0]}"):
            try:
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                if os.path.exists(info_path):
                    os.remove(info_path)
                messagebox.showinfo("Success", "File permanently deleted!")
                self.refresh_quarantine()
            except Exception as e:
                messagebox.showerror("Error", f"Delete error:\n{str(e)}")

    def refresh_history(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        history = self.database.get_scan_history()
        for record in history:
            timestamp = record[1][:19] if record[1] else "N/A"
            file_path = record[2] if len(record[2]) < 50 else "..." + record[2][-47:]
            status = "TEHDIT" if record[3] else "TEMIZ"
            threat_type = record[4] or "Clean"
            action = record[7] or "Scanned"
            self.history_tree.insert("", "end", values=(
                timestamp,
                file_path,
                status,
                threat_type,
                action
            ))

    def clear_history(self):
        if messagebox.askyesno("Clear History", "Do you want to delete all scan history?"):
            try:
                conn = sqlite3.connect(self.database.db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_history")
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", "Scan history cleared!")
                self.refresh_history()
                self.update_stats()
            except Exception as e:
                messagebox.showerror("Error", f"History clearing error:\n{str(e)}")

    def browse_quarantine_folder(self):
        folder = filedialog.askdirectory(title="Select new quarantine folder")
        if folder:
            self.quar_path_entry.delete(0, tk.END)
            self.quar_path_entry.insert(0, folder)
            self.quarantine.quarantine_dir = folder
            os.makedirs(folder, exist_ok=True)

    def update_stats(self):
        try:
            stats = self.database.get_statistics()
            stats_text = f"""SCAN STATISTICS
{'='*50}
Total Scans: {stats['total_scans']:,}
Threats Detected: {stats['threats_found']:,}
Clean Files: {stats['clean_files']:,}
Last Scan: {stats['last_scan'][:19] if stats['last_scan'] != 'No scans performed yet' else stats['last_scan']}

PERFORMANCE
{'='*50}
Detection Rate: %{(stats['threats_found']/stats['total_scans']*100) if stats['total_scans'] > 0 else 0:.2f}
Success Rate: %{(stats['clean_files']/stats['total_scans']*100) if stats['total_scans'] > 0 else 0:.2f}

SECURITY STATUS
{'='*50}
Quarantine Folder: Active
Database: Connected
Scan Engine: Ready
"""
            self.stats_text.delete("1.0", tk.END)
            self.stats_text.insert("1.0", stats_text)
        except Exception as e:
            self.stats_text.delete("1.0", tk.END)
            self.stats_text.insert("1.0", f"Stats loading error: {str(e)}")

    def update_system_info(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            process_count = len(list(psutil.process_iter()))
            system_text = f"""SYSTEM STATUS
{'='*40}
CPU Usage: %{cpu_percent:.1f}
RAM Usage: %{memory.percent:.1f} ({memory.used/1024/1024/1024:.1f}GB / {memory.total/1024/1024/1024:.1f}GB)
Disk Usage: %{disk.percent:.1f} ({disk.used/1024/1024/1024:.1f}GB / {disk.total/1024/1024/1024:.1f}GB)
Active Processes: {process_count}

ANTIVIRUS STATUS
{'='*40}
Scan Engine: Active
Quarantine: Ready
Database: Connected
Real-Time Protection: Inactive
"""
            self.system_text.delete("1.0", tk.END)
            self.system_text.insert("1.0", system_text)
        except Exception as e:
            self.system_text.delete("1.0", tk.END)
            self.system_text.insert("1.0", f"System information loading error: {str(e)}")

    def run(self):
        self.refresh_quarantine()
        self.refresh_history()
        self.root.mainloop()

def main():
    try:
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                messagebox.showwarning("Warning", 
                    "This program requires administrator privileges for some features.\n"
                    "Please run the program with 'Run as Administrator' for full functionality.")
        except:
            pass
        app = AntivirusGUI()
        app.run()
    except Exception as e:
        messagebox.showerror("Critical Error", f"Program could not start:\n{str(e)}")
        print(f"Error detail: {e}")

if __name__ == "__main__":
    required_packages = ['customtkinter', 'psutil']
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    if missing_packages:
        print("Missing libraries detected!")
        print("Please run the following command:")
        print(f"pip install {' '.join(missing_packages)}")
        input("\nAfter installing libraries, press Enter to continue...")
        still_missing = []
        for package in missing_packages:
            try:
                __import__(package)
            except ImportError:
                still_missing.append(package)
        if still_missing:
            print(f"Still missing libraries: {', '.join(still_missing)}")
            print("Please install the libraries and try again.")
            sys.exit(1)
    print("All libraries are ready!")
    print("Starting VSChecker...")
    main()
