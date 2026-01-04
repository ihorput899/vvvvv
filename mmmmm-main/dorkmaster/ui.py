# ui.py - GUI for DorkStrike PRO

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import csv
import json
from datetime import datetime
from scanner import DorkScanner
from patterns import DorkPatterns
import xml.etree.ElementTree as ET

class DorkStrikeUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DorkStrike PRO - Продвинутый сканер Google Dork")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Initialize scanner
        self.scanner = None
        self.scanning = False
        self.scan_thread = None

        # Findings storage for filtering
        self.all_findings = []

        # Create GUI elements
        self.create_widgets()

        # Initialize patterns for category info
        self.patterns = DorkPatterns()

        # Data storage
        self.proxies = []

    def create_widgets(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="DorkStrike PRO", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))

        # ========== CONTROL BUTTONS ==========
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        self.start_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan, width=12)
        self.start_button.pack(side=tk.LEFT, padx=2)

        self.stop_button = ttk.Button(control_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, width=12)
        self.stop_button.pack(side=tk.LEFT, padx=2)

        self.save_results_button = ttk.Button(control_frame, text="Save Results", command=self.save_results, width=12, state=tk.DISABLED)
        self.save_results_button.pack(side=tk.LEFT, padx=2)

        self.open_results_button = ttk.Button(control_frame, text="Open Results Folder", command=self.open_results_folder, width=16)
        self.open_results_button.pack(side=tk.LEFT, padx=2)

        # ========== SETTINGS FRAME ==========
        settings_frame = ttk.LabelFrame(main_frame, text="Scan Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        # Dork Query
        ttk.Label(settings_frame, text="Dork Query:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.dork_var = tk.StringVar()
        self.dork_entry = ttk.Entry(settings_frame, textvariable=self.dork_var, width=60)
        self.dork_entry.grid(row=0, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10))
        self.dork_entry.insert(0, "site:example.com filetype:env")

        # Category selection (moved here to replace domain)
        ttk.Label(settings_frame, text="Category:").grid(row=0, column=4, sticky=tk.W, padx=(20, 10))
        self.category_var = tk.StringVar(value="ALL")
        category_combo = ttk.Combobox(settings_frame, textvariable=self.category_var,
                                    values=["ALL", "CRYPTO", "SECRETS", "VULNERABILITIES"], state="readonly", width=12)
        category_combo.grid(row=0, column=5, sticky=tk.W, padx=(0, 10))

        # Delay and Toggles
        ttk.Label(settings_frame, text="Delay (sec):").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.delay_var = tk.StringVar(value="5")
        delay_entry = ttk.Entry(settings_frame, textvariable=self.delay_var, width=8)
        delay_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=5)

        # DNS Verification toggle
        self.dns_verify_var = tk.BooleanVar(value=True)
        dns_check = ttk.Checkbutton(settings_frame, text="DNS Verification", variable=self.dns_verify_var)
        dns_check.grid(row=1, column=2, sticky=tk.W, padx=(20, 10), pady=5)

        # RAW Mode toggle
        self.raw_mode_var = tk.BooleanVar(value=False)
        raw_check = ttk.Checkbutton(settings_frame, text="RAW Mode", variable=self.raw_mode_var)
        raw_check.grid(row=1, column=3, sticky=tk.W, padx=(10, 0), pady=5)

        # User Agent Rotation toggle
        self.ua_rotate_var = tk.BooleanVar(value=True)
        ua_check = ttk.Checkbutton(settings_frame, text="Rotate User Agents", variable=self.ua_rotate_var)
        ua_check.grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=5)

        # Threads and Depth
        ttk.Label(settings_frame, text="Threads:").grid(row=2, column=1, sticky=tk.W, padx=(20, 5), pady=5)
        self.threads_var = tk.IntVar(value=10)
        threads_spin = tk.Spinbox(settings_frame, from_=1, to=50, textvariable=self.threads_var, width=8)
        threads_spin.grid(row=2, column=2, sticky=tk.W, padx=(0, 10), pady=5)

        ttk.Label(settings_frame, text="Depth:").grid(row=2, column=3, sticky=tk.W, padx=(5, 5), pady=5)
        self.depth_var = tk.IntVar(value=3)
        depth_spin = tk.Spinbox(settings_frame, from_=1, to=10, textvariable=self.depth_var, width=8)
        depth_spin.grid(row=2, column=4, sticky=tk.W, pady=5)

        # Search Engines
        ttk.Label(settings_frame, text="Engines:").grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        engines_frame = ttk.Frame(settings_frame)
        engines_frame.grid(row=3, column=1, columnspan=4, sticky=tk.W, pady=5)

        self.engine_vars = {}
        engines = ['google', 'duckduckgo', 'bing', 'shodan', 'wayback']
        engine_names = {'google': 'Google', 'duckduckgo': 'DuckDuckGo', 'bing': 'Bing', 'shodan': 'Shodan', 'wayback': 'Wayback'}
        for i, engine in enumerate(engines):
            var = tk.BooleanVar(value=(engine == 'google'))
            self.engine_vars[engine] = var
            ttk.Checkbutton(engines_frame, text=engine_names[engine], variable=var).grid(row=0, column=i, sticky=tk.W, padx=(0, 15))

        # ========== PROXY FRAME ==========
        proxy_frame = ttk.LabelFrame(main_frame, text="Proxy Management", padding="10")
        proxy_frame.pack(fill=tk.X, pady=(0, 10))
        proxy_frame.columnconfigure(1, weight=1)

        # Proxy Type Dropdown
        ttk.Label(proxy_frame, text="Proxy Type:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.proxy_type_var = tk.StringVar(value="SOCKS5")
        proxy_type_combo = ttk.Combobox(proxy_frame, textvariable=self.proxy_type_var,
                                      values=["SOCKS5", "HTTPS", "HTTP"], state="readonly", width=10)
        proxy_type_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))

        # Proxy control buttons
        proxy_btn_frame = ttk.Frame(proxy_frame)
        proxy_btn_frame.grid(row=0, column=2, sticky=tk.W)

        ttk.Button(proxy_btn_frame, text="Load File", command=self.load_proxies_from_file, width=10).pack(side=tk.LEFT, padx=(5, 2))
        ttk.Button(proxy_btn_frame, text="Test All", command=self.test_all_proxies, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(proxy_btn_frame, text="Clear All", command=self.clear_all_proxies, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(proxy_btn_frame, text="Add Proxy", command=self.add_proxy_dialog, width=10).pack(side=tk.LEFT, padx=2)

        # Proxy List with scrollbars
        proxy_list_frame = ttk.Frame(proxy_frame)
        proxy_list_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
        proxy_list_frame.columnconfigure(0, weight=1)
        proxy_list_frame.rowconfigure(0, weight=1)

        self.proxy_tree = ttk.Treeview(proxy_list_frame, columns=("Proxy", "Status"), show="headings", height=5)
        self.proxy_tree.heading("Proxy", text="Proxy")
        self.proxy_tree.heading("Status", text="Status")
        self.proxy_tree.column("Proxy", width=300)
        self.proxy_tree.column("Status", width=100)
        self.proxy_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        proxy_tree_scroll = ttk.Scrollbar(proxy_list_frame, orient=tk.VERTICAL, command=self.proxy_tree.yview)
        proxy_tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.proxy_tree.configure(yscrollcommand=proxy_tree_scroll.set)

        # ========== PROGRESS BAR ==========
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))

        # ========== LIVE STATS ==========
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))

        # Top stats line
        self.stats_line1_var = tk.StringVar(value="URLs Scanned: 0 | Findings: 0 | Req/min: 0 | Wayback URLs: 0 | Downloaded: 0 | RAW Matches: 0")
        stats_line1 = ttk.Label(stats_frame, textvariable=self.stats_line1_var, font=("Courier", 9))
        stats_line1.pack(fill=tk.X)

        # Bottom stats line  
        self.stats_line2_var = tk.StringVar(value="Mode: STRICT | DNS: ON | Proxies: 0 | UA Rotation: ON")
        stats_line2 = ttk.Label(stats_frame, textvariable=self.stats_line2_var, font=("Courier", 9))
        stats_line2.pack(fill=tk.X)

        # ========== LOG AREA ==========
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        # Findings View
        findings_frame = ttk.Frame(log_frame)
        findings_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)

        # Findings treeview
        columns = ("Type", "Pattern", "URL", "Match", "Verification")
        self.findings_tree = ttk.Treeview(findings_frame, columns=columns, show="headings", height=10)

        for col in columns:
            self.findings_tree.heading(col, text=col)
            self.findings_tree.column(col, width=120)

        findings_scrollbar = ttk.Scrollbar(findings_frame, orient=tk.VERTICAL, command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=findings_scrollbar.set)

        self.findings_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        findings_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Log entry
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8)
        self.log_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X)

    def start_scan(self):
        dork = self.dork_var.get().strip()
        if not dork or dork == "site:example.com filetype:env":
            messagebox.showerror("Error", "Please enter a valid dork query")
            return

        if not self.scanning:
            self.scanning = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.save_results_button.config(state=tk.DISABLED)

            # Clear previous results
            for item in self.findings_tree.get_children():
                self.findings_tree.delete(item)
            self.log_text.delete(1.0, tk.END)
            self.progress_var.set(0)
            self.all_findings = []

            # Get selected search engines
            search_engines = [engine for engine, var in self.engine_vars.items() if var.get()]

            # Get proxies from list
            proxies = []
            for item in self.proxy_tree.get_children():
                proxy = self.proxy_tree.item(item)['values'][0]
                proxies.append(proxy)

            # Get delay
            try:
                delay = float(self.delay_var.get())
            except:
                delay = 5.0

            # Initialize scanner
            self.scanner = DorkScanner(
                proxies=proxies,
                search_engines=search_engines,
                delay=delay,
                dns_verify=self.dns_verify_var.get(),
                proxy_type=self.proxy_type_var.get(),
                ua_rotate=self.ua_rotate_var.get(),
                raw_mode=self.raw_mode_var.get()
            )

            # Update stats display
            self.update_live_stats()

            # Start scan in thread
            self.scan_thread = threading.Thread(
                target=self.run_scan,
                args=(dork, self.category_var.get(), self.threads_var.get())
            )
            self.scan_thread.daemon = True
            self.scan_thread.start()

    def run_scan(self, dork, category, threads):
        try:
            # For this implementation, we'll use domain from dork if possible
            domain = "unknown"
            if 'site:' in dork:
                import re
                match = re.search(r'site:([\w\.]+)', dork)
                if match:
                    domain = match.group(1)

            results = self.scanner.scan(
                domain, category, threads,
                self.progress_callback,
                self.log_callback,
                self.finding_callback
            )

            # Update statistics
            self.root.after(0, lambda: self.update_statistics(results))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
        finally:
            self.root.after(0, self.scan_finished)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop_scan()
        self.scan_finished()

    def scan_finished(self):
        self.scanning = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_results_button.config(state=tk.NORMAL)
        self.status_var.set("Scan completed")

    def progress_callback(self, progress):
        self.root.after(0, lambda: self.progress_var.set(progress))
        self.root.after(0, self.update_live_stats)

    def update_live_stats(self):
        if not self.scanner:
            return

        # Line 1: URLs Scanned: 0 | Findings: 0 | Req/min: 0 | Wayback URLs: 0 | Downloaded: 0 | RAW Matches: 0
        urls_scanned = getattr(self.scanner, 'urls_scanned', 0)
        findings = len(self.all_findings)
        req_per_min = getattr(self.scanner, 'req_per_min', 0)
        wayback_urls = getattr(self.scanner, 'total_urls', 0)
        downloaded = getattr(self.scanner, 'download_success_count', 0)
        raw_matches = getattr(self.scanner, 'regex_match_count', 0)
        
        line1 = f"URLs Scanned: {urls_scanned} | Findings: {findings} | Req/min: {req_per_min} | Wayback URLs: {wayback_urls} | Downloaded: {downloaded} | RAW Matches: {raw_matches}"
        self.stats_line1_var.set(line1)

        # Line 2: Mode: STRICT | DNS: ON | Proxies: 0 | UA Rotation: ON
        mode = "RAW" if self.scanner.raw_mode else "STRICT"
        dns = "ON" if self.dns_verify_var.get() else "OFF"
        proxies = len(self.proxies)
        ua = "ON" if self.ua_rotate_var.get() else "OFF"
        
        line2 = f"Mode: {mode} | DNS: {dns} | Proxies: {proxies} | UA Rotation: {ua}"
        self.stats_line2_var.set(line2)

    def log_callback(self, message):
        self.root.after(0, lambda: self.log_text.insert(tk.END, message + "\n"))
        self.root.after(0, lambda: self.log_text.see(tk.END))
        self.root.after(0, lambda: self.status_var.set(message))

    def finding_callback(self, finding_type, pattern, url, match, verification):
        finding = (finding_type, pattern, url, match, verification)
        self.all_findings.append(finding)
        self.root.after(0, lambda: self.findings_tree.insert("", tk.END, values=finding))

    def update_statistics(self, results):
        self.stats_line1_var.set(f"URLs Scanned: {results.get('total_urls', 0)} | Findings: {results.get('findings_count', 0)} | Req/min: {results.get('req_per_min', 0)} | Wayback URLs: {results.get('total_urls', 0)} | Downloaded: {results.get('download_success', 0)} | RAW Matches: {results.get('regex_matches', 0)}")
        
        mode = "RAW" if self.scanner and self.scanner.raw_mode else "STRICT"
        dns_status = "ON" if self.dns_verify_var.get() else "OFF"
        proxy_count = len(self.proxies)
        ua_status = "ON" if self.ua_rotate_var.get() else "OFF"
        
        self.stats_line2_var.set(f"Mode: {mode} | DNS: {dns_status} | Proxies: {proxy_count} | UA Rotation: {ua_status}")

    def save_results(self):
        if not self.all_findings:
            messagebox.showwarning("Warning", "No results to save")
            return

        # Ask for format
        format_dialog = tk.Toplevel(self.root)
        format_dialog.title("Select Export Format")
        format_dialog.geometry("300x200")
        format_dialog.transient(self.root)
        format_dialog.grab_set()

        ttk.Label(format_dialog, text="Choose export format:").pack(pady=10)

        format_var = tk.StringVar(value="TXT")
        
        formats = [("TXT", "TXT"), ("JSON", "JSON"), ("CSV", "CSV"), ("XML", "XML")]
        for text, value in formats:
            ttk.Radiobutton(format_dialog, text=text, variable=format_var, value=value).pack(anchor=tk.W, padx=20)

        def do_save():
            fmt = format_var.get()
            format_dialog.destroy()
            
            # Create results directory
            results_dir = os.path.expanduser("~/Desktop/dorkmaster-results")
            os.makedirs(results_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dork_results_{timestamp}.{fmt.lower()}"
            filepath = os.path.join(results_dir, filename)

            try:
                if fmt == "TXT":
                    with open(filepath, 'w') as f:
                        f.write(f"DorkStrike PRO Results\n")
                        f.write(f"Generated: {datetime.now()}\n")
                        f.write("="*50 + "\n\n")
                        for finding in self.all_findings:
                            f.write(f"Type: {finding[0]}\n")
                            f.write(f"Pattern: {finding[1]}\n")
                            f.write(f"URL: {finding[2]}\n")
                            f.write(f"Match: {finding[3]}\n")
                            f.write(f"Verification: {finding[4]}\n")
                            f.write("-"*30 + "\n")

                elif fmt == "JSON":
                    results = []
                    for finding in self.all_findings:
                        results.append({
                            "type": finding[0],
                            "pattern": finding[1],
                            "url": finding[2],
                            "match": finding[3],
                            "verification": finding[4]
                        })
                    with open(filepath, 'w') as f:
                        json.dump(results, f, indent=2)

                elif fmt == "CSV":
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Type", "Pattern", "URL", "Match", "Verification"])
                        for finding in self.all_findings:
                            writer.writerow(finding)

                elif fmt == "XML":
                    root = ET.Element("results")
                    for finding in self.all_findings:
                        item = ET.SubElement(root, "finding")
                        ET.SubElement(item, "type").text = finding[0]
                        ET.SubElement(item, "pattern").text = finding[1]
                        ET.SubElement(item, "url").text = finding[2]
                        ET.SubElement(item, "match").text = finding[3]
                        ET.SubElement(item, "verification").text = finding[4]
                    
                    tree = ET.ElementTree(root)
                    tree.write(filepath, encoding='utf-8', xml_declaration=True)

                messagebox.showinfo("Success", f"Results saved to:\n{filepath}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")

        ttk.Button(format_dialog, text="Save", command=do_save).pack(pady=10)

    def open_results_folder(self):
        results_dir = os.path.expanduser("~/Desktop/dorkmaster-results")
        os.makedirs(results_dir, exist_ok=True)

        if os.name == 'nt':  # Windows
            os.startfile(results_dir)
        elif os.name == 'posix':  # Linux/Mac
            if os.path.exists('/usr/bin/xdg-open'):
                os.system(f"xdg-open '{results_dir}'")
            elif os.path.exists('/usr/bin/open'):
                os.system(f"open '{results_dir}'")
            else:
                messagebox.showinfo("Info", f"Results folder:\n{results_dir}")
        else:
            messagebox.showinfo("Info", f"Results folder:\n{results_dir}")

    # Proxy Management Functions
    def load_proxies_from_file(self):
        file_path = filedialog.askopenfilename(
            title="Load Proxies",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        proxy = line.strip()
                        if proxy and not proxy.startswith('#'):
                            self.add_proxy_to_list(proxy)
                self.log_callback(f"Loaded proxies from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load proxies: {str(e)}")

    def test_all_proxies(self):
        if not self.proxies:
            messagebox.showwarning("Warning", "No proxies to test")
            return

        self.log_callback(f"Testing {len(self.proxies)} proxies...")
        
        def test_thread():
            working = []
            for i, proxy in enumerate(self.proxies):
                if self.scanner and self.scanner.test_proxy(proxy):
                    working.append(proxy)
                    self.root.after(0, lambda p=proxy: self.update_proxy_status(p, "Working"))
                else:
                    self.root.after(0, lambda p=proxy: self.update_proxy_status(p, "Failed"))
            
            self.root.after(0, lambda: self.log_callback(f"Proxy test complete: {len(working)}/{len(self.proxies)} working"))
        
        threading.Thread(target=test_thread, daemon=True).start()

    def clear_all_proxies(self):
        self.proxies = []
        for item in self.proxy_tree.get_children():
            self.proxy_tree.delete(item)
        self.log_callback("All proxies cleared")

    def add_proxy_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Proxy")
        dialog.geometry("400x100")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Enter proxy (ip:port or user:pass@ip:port):").pack(pady=5)
        proxy_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=proxy_var, width=40).pack(pady=5)

        def add():
            proxy = proxy_var.get().strip()
            if proxy:
                self.add_proxy_to_list(proxy)
                dialog.destroy()

        ttk.Button(dialog, text="Add", command=add).pack(pady=5)

    def add_proxy_to_list(self, proxy):
        if proxy not in self.proxies:
            self.proxies.append(proxy)
            self.proxy_tree.insert("", tk.END, values=(proxy, "Unknown"))

    def test_selected_proxy(self):
        selection = self.proxy_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No proxy selected")
            return

        item = selection[0]
        values = self.proxy_tree.item(item)['values']
        proxy = values[0]

        self.log_callback(f"Testing proxy: {proxy}")
        
        def test():
            if self.scanner and self.scanner.test_proxy(proxy):
                self.root.after(0, lambda: self.update_proxy_status(proxy, "Working"))
            else:
                self.root.after(0, lambda: self.update_proxy_status(proxy, "Failed"))
        
        threading.Thread(target=test, daemon=True).start()

    def delete_selected_proxy(self):
        selection = self.proxy_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "No proxy selected")
            return

        for item in selection:
            values = self.proxy_tree.item(item)['values']
            proxy = values[0]
            if proxy in self.proxies:
                self.proxies.remove(proxy)
            self.proxy_tree.delete(item)

    def update_proxy_status(self, proxy, status):
        for item in self.proxy_tree.get_children():
            values = self.proxy_tree.item(item)['values']
            if values and values[0] == proxy:
                self.proxy_tree.item(item, values=(proxy, status))
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = DorkStrikeUI(root)
    root.mainloop()