# ui.py - GUI for DorkStrike PRO

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import csv
import json
import queue
from datetime import datetime
from scanner import DorkScanner
from patterns import DorkPatterns
import xml.etree.ElementTree as ET

# Translation Dictionary
TRANSLATIONS = {
    # Buttons
    'start_scan': 'Начать сканирование',
    'stop_scan': 'Остановить сканирование',
    'save_results': 'Сохранить результаты',
    'open_results': 'Открыть папку с результатами',
    
    # Settings
    'scan_settings': 'Параметры сканирования',
    'dork_query': 'Поисковый запрос:',
    'category': 'Категория:',
    'delay': 'Задержка (сек):',
    'dns_verification': 'Проверка DNS',
    'raw_mode': 'Режим RAW',
    'rotate_ua': 'Ротация User-Agent',
    'threads': 'Потоки:',
    'depth': 'Глубина:',
    'engines': 'Поисковики:',
    'sources': 'Источники:',
    
    # Categories
    'cat_all': 'ВСЕ',
    'cat_crypto': 'КРИПТО',
    'cat_secrets': 'СЕКРЕТЫ',
    'cat_vulnerabilities': 'УЯЗВИМОСТИ',
    
    # Proxy
    'proxy_mgmt': 'Управление прокси',
    'proxy_type': 'Тип прокси:',
    'load_file': 'Загрузить файл',
    'test_all': 'Протестировать все',
    'clear_all': 'Очистить все',
    'add_proxy': 'Добавить прокси',
    'proxy_col': 'Прокси',
    'status_col': 'Статус',
    'enter_proxy_msg': 'Введите прокси (ip:port или user:pass@ip:port):',
    'add_btn': 'Добавить',
    'working': 'Работает',
    'failed': 'Ошибка',
    'unknown': 'Неизвестно',
    
    # Stats
    'urls_scanned_stat': 'Сканировано URL:',
    'findings_stat': 'Найдено:',
    'req_min_stat': 'Запр./мин:',
    'wayback_urls_stat': 'URL из Wayback:',
    'github_files_stat': 'Файлов GitHub:',
    'downloaded_stat': 'Загружено:',
    'raw_matches_stat': 'Совпадений RAW:',
    'mode_stat': 'Режим:',
    'dns_stat': 'DNS:',
    'proxies_stat': 'Прокси:',
    'ua_rotation_stat': 'Ротация UA:',
    'on': 'ВКЛ',
    'off': 'ВЫКЛ',
    'strict': 'СТРОГИЙ',
    'raw': 'RAW',
    
    # Log & Findings
    'log_label': 'Лог',
    'findings_view': 'Результаты поиска',
    'col_type': 'Тип',
    'col_pattern': 'Паттерн',
    'col_url': 'URL',
    'col_match': 'Совпадение',
    'col_status': 'Статус',
    'col_source': 'Источник',
    'col_verification': 'Проверка',
    'ver_raw': 'RAW',
    'ver_verified': 'ПРОВЕРЕНО',
    
    # Messages & Dialogs
    'ready': 'Готов',
    'error': 'Ошибка',
    'success': 'Успех',
    'warning': 'Внимание',
    'info': 'Информация',
    'enter_valid_dork': 'Пожалуйста, введите корректный поисковый запрос',
    'scan_failed_msg': 'Ошибка сканирования: ',
    'scan_completed_msg': 'Сканирование завершено',
    'no_results_to_save': 'Нет результатов для сохранения',
    'select_export_format': 'Выбор формата экспорта',
    'choose_export_format': 'Выберите формат экспорта:',
    'results_saved_to': 'Результаты сохранены в:',
    'failed_to_save_results': 'Не удалось сохранить результаты: ',
    'load_proxies_title': 'Загрузить прокси',
    'text_files': 'Текстовые файлы',
    'all_files': 'Все файлы',
    'loaded_proxies_log': 'Загружено прокси из ',
    'failed_to_load_proxies': 'Не удалось загрузить прокси: ',
    'no_proxies_to_test': 'Нет прокси для тестирования',
    'testing_x_proxies': 'Тестирование {count} прокси...',
    'proxy_test_complete': 'Тестирование прокси завершено: {working}/{total} работают',
    'all_proxies_cleared': 'Все прокси очищены',
    'no_proxy_selected': 'Прокси не выбран',
    'testing_proxy_log': 'Тестирование прокси: ',

    # Generic
    'save': 'Сохранить',
    'select_sources_msg': 'Пожалуйста, выберите хотя бы один источник (Wayback или GitHub)',
}

class DorkStrikeUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DorkStrike PRO")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Initialize scanner
        self.scanner = None
        self.scanning = False
        self.scan_thread = None

        # Queue for real-time results
        self.findings_queue = queue.Queue()
        self.root.after(100, self.process_findings_queue)

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

        self.start_button = ttk.Button(control_frame, text=TRANSLATIONS['start_scan'], command=self.start_scan, width=18)
        self.start_button.pack(side=tk.LEFT, padx=2)

        self.stop_button = ttk.Button(control_frame, text=TRANSLATIONS['stop_scan'], command=self.stop_scan, state=tk.DISABLED, width=22)
        self.stop_button.pack(side=tk.LEFT, padx=2)

        self.save_results_button = ttk.Button(control_frame, text=TRANSLATIONS['save_results'], command=self.save_results, width=20, state=tk.DISABLED)
        self.save_results_button.pack(side=tk.LEFT, padx=2)

        self.open_results_button = ttk.Button(control_frame, text=TRANSLATIONS['open_results'], command=self.open_results_folder, width=28)
        self.open_results_button.pack(side=tk.LEFT, padx=2)

        # ========== SETTINGS FRAME ==========
        settings_frame = ttk.LabelFrame(main_frame, text=TRANSLATIONS['scan_settings'], padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        # Dork Query
        ttk.Label(settings_frame, text=TRANSLATIONS['dork_query']).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.dork_var = tk.StringVar()
        self.dork_entry = ttk.Entry(settings_frame, textvariable=self.dork_var, width=60)
        self.dork_entry.grid(row=0, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10))
        self.dork_entry.insert(0, "site:example.com filetype:env")

        # Category selection (moved here to replace domain)
        ttk.Label(settings_frame, text=TRANSLATIONS['category']).grid(row=0, column=4, sticky=tk.W, padx=(20, 10))
        self.category_var = tk.StringVar(value=TRANSLATIONS['cat_all'])
        category_combo = ttk.Combobox(settings_frame, textvariable=self.category_var,
                                    values=[TRANSLATIONS['cat_all'], TRANSLATIONS['cat_crypto'], TRANSLATIONS['cat_secrets'], TRANSLATIONS['cat_vulnerabilities']], state="readonly", width=15)
        category_combo.grid(row=0, column=5, sticky=tk.W, padx=(0, 10))

        # Delay and Toggles
        ttk.Label(settings_frame, text=TRANSLATIONS['delay']).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.delay_var = tk.StringVar(value="5")
        delay_entry = ttk.Entry(settings_frame, textvariable=self.delay_var, width=8)
        delay_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=5)

        # RAW Mode toggle
        self.raw_mode_var = tk.BooleanVar(value=False)
        raw_check = ttk.Checkbutton(settings_frame, text=TRANSLATIONS['raw_mode'], variable=self.raw_mode_var)
        raw_check.grid(row=1, column=2, sticky=tk.W, padx=(20, 10), pady=5)

        # User Agent Rotation toggle
        self.ua_rotate_var = tk.BooleanVar(value=True)
        ua_check = ttk.Checkbutton(settings_frame, text=TRANSLATIONS['rotate_ua'], variable=self.ua_rotate_var)
        ua_check.grid(row=1, column=3, sticky=tk.W, padx=(10, 0), pady=5)

        # Threads and Depth
        ttk.Label(settings_frame, text=TRANSLATIONS['threads']).grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        self.threads_var = tk.IntVar(value=10)
        threads_spin = tk.Spinbox(settings_frame, from_=1, to=50, textvariable=self.threads_var, width=8)
        threads_spin.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=5)

        ttk.Label(settings_frame, text=TRANSLATIONS['depth']).grid(row=2, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        self.depth_var = tk.IntVar(value=3)
        depth_spin = tk.Spinbox(settings_frame, from_=1, to=10, textvariable=self.depth_var, width=8)
        depth_spin.grid(row=2, column=3, sticky=tk.W, pady=5)

        # Sources
        ttk.Label(settings_frame, text=TRANSLATIONS['sources']).grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        sources_frame = ttk.Frame(settings_frame)
        sources_frame.grid(row=3, column=1, columnspan=5, sticky=tk.W, pady=5)

        self.source_vars = {}
        sources = {
            'wayback': 'Wayback Machine (история домена)',
            'github': 'GitHub (утёкшие репо)'
        }
        for source, label in sources.items():
            var = tk.BooleanVar(value=(source == 'wayback'))
            self.source_vars[source] = var
            ttk.Checkbutton(sources_frame, text=label, variable=var).pack(anchor=tk.W, pady=2)

        # Search Engines (legacy)
        ttk.Label(settings_frame, text=TRANSLATIONS['engines']).grid(row=4, column=0, sticky=tk.W, padx=(0, 10), pady=5)
        engines_frame = ttk.Frame(settings_frame)
        engines_frame.grid(row=4, column=1, columnspan=4, sticky=tk.W, pady=5)

        self.engine_vars = {}
        engines = ['google', 'duckduckgo', 'bing', 'shodan', 'wayback']
        engine_names = {'google': 'Google', 'duckduckgo': 'DuckDuckGo', 'bing': 'Bing', 'shodan': 'Shodan', 'wayback': 'Wayback'}
        for i, engine in enumerate(engines):
            var = tk.BooleanVar(value=(engine == 'google'))
            self.engine_vars[engine] = var
            ttk.Checkbutton(engines_frame, text=engine_names[engine], variable=var).grid(row=0, column=i, sticky=tk.W, padx=(0, 15))

        # ========== PROXY FRAME ==========
        proxy_frame = ttk.LabelFrame(main_frame, text=TRANSLATIONS['proxy_mgmt'], padding="10")
        proxy_frame.pack(fill=tk.X, pady=(0, 10))
        proxy_frame.columnconfigure(1, weight=1)

        # Proxy Type Dropdown
        ttk.Label(proxy_frame, text=TRANSLATIONS['proxy_type']).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.proxy_type_var = tk.StringVar(value="SOCKS5")
        proxy_type_combo = ttk.Combobox(proxy_frame, textvariable=self.proxy_type_var,
                                      values=["SOCKS5", "HTTPS", "HTTP"], state="readonly", width=10)
        proxy_type_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))

        # Proxy control buttons
        proxy_btn_frame = ttk.Frame(proxy_frame)
        proxy_btn_frame.grid(row=0, column=2, sticky=tk.W)

        ttk.Button(proxy_btn_frame, text=TRANSLATIONS['load_file'], command=self.load_proxies_from_file, width=15).pack(side=tk.LEFT, padx=(5, 2))
        ttk.Button(proxy_btn_frame, text=TRANSLATIONS['test_all'], command=self.test_all_proxies, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(proxy_btn_frame, text=TRANSLATIONS['clear_all'], command=self.clear_all_proxies, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Button(proxy_btn_frame, text=TRANSLATIONS['add_proxy'], command=self.add_proxy_dialog, width=15).pack(side=tk.LEFT, padx=2)

        # Proxy List with scrollbars
        proxy_list_frame = ttk.Frame(proxy_frame)
        proxy_list_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))
        proxy_list_frame.columnconfigure(0, weight=1)
        proxy_list_frame.rowconfigure(0, weight=1)

        self.proxy_tree = ttk.Treeview(proxy_list_frame, columns=("Proxy", "Status"), show="headings", height=5)
        self.proxy_tree.heading("Proxy", text=TRANSLATIONS['proxy_col'])
        self.proxy_tree.heading("Status", text=TRANSLATIONS['status_col'])
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
        self.stats_line1_var = tk.StringVar(
            value=f"{TRANSLATIONS['urls_scanned_stat']} 0 | {TRANSLATIONS['findings_stat']} 0 (W:0 G:0) | {TRANSLATIONS['req_min_stat']} 0 | {TRANSLATIONS['wayback_urls_stat']} 0 | {TRANSLATIONS['github_files_stat']} 0 | {TRANSLATIONS['downloaded_stat']} 0 | {TRANSLATIONS['raw_matches_stat']} 0"
        )
        stats_line1 = ttk.Label(stats_frame, textvariable=self.stats_line1_var, font=("Courier", 9))
        stats_line1.pack(fill=tk.X)

        # Bottom stats line  
        self.stats_line2_var = tk.StringVar(value=f"{TRANSLATIONS['mode_stat']} {TRANSLATIONS['strict']} | {TRANSLATIONS['dns_stat']} {TRANSLATIONS['on']} | {TRANSLATIONS['proxies_stat']} 0 | {TRANSLATIONS['ua_rotation_stat']} {TRANSLATIONS['on']}")
        stats_line2 = ttk.Label(stats_frame, textvariable=self.stats_line2_var, font=("Courier", 9))
        stats_line2.pack(fill=tk.X)

        # ========== LOG AREA ==========
        log_frame = ttk.LabelFrame(main_frame, text=TRANSLATIONS['log_label'], padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        # Findings View
        findings_frame = ttk.Frame(log_frame)
        findings_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)

        # Findings treeview with Status and Source columns
        columns = ("Type", "Source", "Pattern", "URL", "Match", "Status", "Verification")
        col_names = {
            "Type": TRANSLATIONS['col_type'],
            "Source": TRANSLATIONS['col_source'],
            "Pattern": TRANSLATIONS['col_pattern'],
            "URL": TRANSLATIONS['col_url'],
            "Match": TRANSLATIONS['col_match'],
            "Status": TRANSLATIONS['col_status'],
            "Verification": TRANSLATIONS['col_verification']
        }
        self.findings_tree = ttk.Treeview(findings_frame, columns=columns, show="headings", height=10)

        # Configure tags for coloring
        self.findings_tree.tag_configure('raw', background='#ffcccc')      # light red
        self.findings_tree.tag_configure('verified', background='#ccffcc') # light green

        for col in columns:
            self.findings_tree.heading(col, text=col_names[col])
            if col == "URL":
                self.findings_tree.column(col, width=200)
            elif col == "Status":
                self.findings_tree.column(col, width=80)
            elif col == "Source":
                self.findings_tree.column(col, width=100)
            else:
                self.findings_tree.column(col, width=120)

        findings_scrollbar = ttk.Scrollbar(findings_frame, orient=tk.VERTICAL, command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=findings_scrollbar.set)

        self.findings_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        findings_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Log entry
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=8)
        self.log_text.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 0))

        # Status bar
        self.status_var = tk.StringVar(value=TRANSLATIONS['ready'])
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X)

    def start_scan(self):
        dork = self.dork_var.get().strip()
        if not dork or dork == "site:example.com filetype:env":
            messagebox.showerror(TRANSLATIONS['error'], TRANSLATIONS['enter_valid_dork'])
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

            # Get selected search engines (legacy)
            search_engines = [engine for engine, var in self.engine_vars.items() if var.get()]

            # Get selected sources
            sources = [source for source, var in self.source_vars.items() if var.get()]
            if not sources:
                messagebox.showerror(TRANSLATIONS['error'], TRANSLATIONS['select_sources_msg'])
                self.scanning = False
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                return

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

            # Update window title to show RAW MODE and sources
            sources_display = "+".join([s.upper() for s in sources])
            if self.raw_mode_var.get():
                self.root.title(f"DorkStrike PRO - 🔴 RAW MODE: {sources_display}")
            else:
                self.root.title("DorkStrike PRO")

            # Initialize scanner
            self.scanner = DorkScanner(
                proxies=proxies,
                search_engines=search_engines,
                sources=sources,
                delay=delay,
                proxy_type=self.proxy_type_var.get(),
                ua_rotate=self.ua_rotate_var.get(),
                raw_mode=self.raw_mode_var.get(),
                ui_callback=self.on_finding_found,
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
        # Map category back to English for scanner
        category_map = {
            TRANSLATIONS['cat_all']: "ALL",
            TRANSLATIONS['cat_crypto']: "CRYPTO",
            TRANSLATIONS['cat_secrets']: "SECRETS",
            TRANSLATIONS['cat_vulnerabilities']: "VULNERABILITIES"
        }
        internal_category = category_map.get(category, "ALL")

        try:
            # For this implementation, we'll use domain from dork if possible
            domain = "unknown"
            if 'site:' in dork:
                import re
                match = re.search(r'site:([\w\.]+)', dork)
                if match:
                    domain = match.group(1)

            results = self.scanner.scan(
                domain, internal_category, threads,
                self.progress_callback,
                self.log_callback
            )

            # Update statistics
            self.root.after(0, lambda: self.update_statistics(results))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(TRANSLATIONS['error'], f"{TRANSLATIONS['scan_failed_msg']}{str(e)}"))
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
        self.status_var.set(TRANSLATIONS['scan_completed_msg'])

    def progress_callback(self, progress):
        self.root.after(0, lambda: self.progress_var.set(progress))
        self.root.after(0, self.update_live_stats)

    def update_live_stats(self):
        if not self.scanner:
            return

        urls_scanned = getattr(self.scanner, 'urls_scanned', 0)
        findings_total = len(self.all_findings)
        req_per_min = getattr(self.scanner, 'req_per_min', 0)

        wayback_urls = getattr(self.scanner, 'wayback_total_urls', 0)
        github_files = getattr(self.scanner, 'github_total_urls', 0)

        downloaded = getattr(self.scanner, 'download_success_count', 0)
        raw_matches = getattr(self.scanner, 'regex_match_count', 0)

        wayback_findings = sum(1 for f in self.all_findings if len(f) > 1 and f[1] == 'WAYBACK')
        github_findings = sum(1 for f in self.all_findings if len(f) > 1 and f[1] == 'GITHUB')

        line1 = (
            f"{TRANSLATIONS['urls_scanned_stat']} {urls_scanned} | "
            f"{TRANSLATIONS['findings_stat']} {findings_total} (W:{wayback_findings} G:{github_findings}) | "
            f"{TRANSLATIONS['req_min_stat']} {req_per_min} | "
            f"{TRANSLATIONS['wayback_urls_stat']} {wayback_urls} | "
            f"{TRANSLATIONS['github_files_stat']} {github_files} | "
            f"{TRANSLATIONS['downloaded_stat']} {downloaded} | "
            f"{TRANSLATIONS['raw_matches_stat']} {raw_matches}"
        )
        self.stats_line1_var.set(line1)

        # Line 2: Mode: STRICT | Proxies: 0 | UA Rotation: ON
        mode = TRANSLATIONS['raw'] if self.scanner.raw_mode else TRANSLATIONS['strict']
        proxies = len(self.proxies)
        ua = TRANSLATIONS['on'] if self.ua_rotate_var.get() else TRANSLATIONS['off']
        
        line2 = f"{TRANSLATIONS['mode_stat']} {mode} | {TRANSLATIONS['proxies_stat']} {proxies} | {TRANSLATIONS['ua_rotation_stat']} {ua}"
        self.stats_line2_var.set(line2)

    def log_callback(self, message):
        self.root.after(0, lambda: self.log_text.insert(tk.END, message + "\n"))
        self.root.after(0, lambda: self.log_text.see(tk.END))
        self.root.after(0, lambda: self.status_var.set(message))

    def on_finding_found(self, finding):
        self.findings_queue.put(finding)

    def process_findings_queue(self):
        try:
            while True:
                finding = self.findings_queue.get_nowait()
                self.add_finding_to_tree(finding)
        except queue.Empty:
            pass
        self.root.after(100, self.process_findings_queue)

    def add_finding_to_tree(self, finding_data):
        # Translate finding type
        type_map = {
            "CRYPTO": TRANSLATIONS['cat_crypto'],
            "SECRETS": TRANSLATIONS['cat_secrets'],
            "VULNERABILITIES": TRANSLATIONS['cat_vulnerabilities']
        }
        t_display = type_map.get(finding_data.get('type'), finding_data.get('type'))
        
        status = finding_data.get('status', 'RAW')
        v_display = TRANSLATIONS['ver_verified'] if status == "VERIFIED" else TRANSLATIONS['ver_raw']
        
        # New order: (Type, Source, Pattern, URL, Match, Status, Verification)
        finding_values = (
            t_display,
            finding_data.get('source', 'WAYBACK'),
            finding_data.get('pattern'),
            finding_data.get('url'),
            finding_data.get('match'),
            status,
            v_display
        )
        
        self.all_findings.append(finding_values)
        tag = 'raw' if status == 'RAW' else 'verified'
        self.findings_tree.insert("", tk.END, values=finding_values, tags=(tag,))
        self.findings_tree.see(self.findings_tree.get_children()[-1])

    def update_statistics(self, results):
        total_urls = results.get('total_urls', 0)
        findings_total = results.get('findings_count', 0)
        req_per_min = results.get('req_per_min', 0)

        wayback_urls = getattr(self.scanner, 'wayback_total_urls', 0) if self.scanner else 0
        github_files = getattr(self.scanner, 'github_total_urls', 0) if self.scanner else 0

        wayback_findings = sum(1 for f in self.all_findings if len(f) > 1 and f[1] == 'WAYBACK')
        github_findings = sum(1 for f in self.all_findings if len(f) > 1 and f[1] == 'GITHUB')

        self.stats_line1_var.set(
            f"{TRANSLATIONS['urls_scanned_stat']} {total_urls} | "
            f"{TRANSLATIONS['findings_stat']} {findings_total} (W:{wayback_findings} G:{github_findings}) | "
            f"{TRANSLATIONS['req_min_stat']} {req_per_min} | "
            f"{TRANSLATIONS['wayback_urls_stat']} {wayback_urls} | "
            f"{TRANSLATIONS['github_files_stat']} {github_files} | "
            f"{TRANSLATIONS['downloaded_stat']} {results.get('download_success', 0)} | "
            f"{TRANSLATIONS['raw_matches_stat']} {results.get('regex_matches', 0)}"
        )

        mode = TRANSLATIONS['raw'] if self.scanner and self.scanner.raw_mode else TRANSLATIONS['strict']
        proxy_count = len(self.proxies)
        ua_status = TRANSLATIONS['on'] if self.ua_rotate_var.get() else TRANSLATIONS['off']

        self.stats_line2_var.set(
            f"{TRANSLATIONS['mode_stat']} {mode} | {TRANSLATIONS['proxies_stat']} {proxy_count} | {TRANSLATIONS['ua_rotation_stat']} {ua_status}"
        )

    def save_results(self):
        if not self.all_findings:
            messagebox.showwarning(TRANSLATIONS['warning'], TRANSLATIONS['no_results_to_save'])
            return

        # Ask for format
        format_dialog = tk.Toplevel(self.root)
        format_dialog.title(TRANSLATIONS['select_export_format'])
        format_dialog.geometry("300x220")
        format_dialog.transient(self.root)
        format_dialog.grab_set()

        ttk.Label(format_dialog, text=TRANSLATIONS['choose_export_format']).pack(pady=10)

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
                        f.write(f"Результаты DorkStrike PRO\n")
                        f.write(f"Сгенерировано: {datetime.now()}\n")
                        f.write("="*50 + "\n\n")
                        for finding in self.all_findings:
                            f.write(f"{TRANSLATIONS['col_type']}: {finding[0]}\n")
                            f.write(f"{TRANSLATIONS['col_source']}: {finding[1]}\n")
                            f.write(f"{TRANSLATIONS['col_pattern']}: {finding[2]}\n")
                            f.write(f"{TRANSLATIONS['col_url']}: {finding[3]}\n")
                            f.write(f"{TRANSLATIONS['col_match']}: {finding[4]}\n")
                            f.write(f"{TRANSLATIONS['col_status']}: {finding[5]}\n")
                            f.write(f"{TRANSLATIONS['col_verification']}: {finding[6]}\n")
                            f.write("-"*30 + "\n")

                elif fmt == "JSON":
                    results = []
                    for finding in self.all_findings:
                        results.append({
                            "type": finding[0],
                            "source": finding[1],
                            "pattern": finding[2],
                            "url": finding[3],
                            "match": finding[4],
                            "status": finding[5],
                            "verification": finding[6],
                        })
                    with open(filepath, 'w') as f:
                        json.dump(results, f, indent=2)

                elif fmt == "CSV":
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([
                            TRANSLATIONS['col_type'],
                            TRANSLATIONS['col_source'],
                            TRANSLATIONS['col_pattern'],
                            TRANSLATIONS['col_url'],
                            TRANSLATIONS['col_match'],
                            TRANSLATIONS['col_status'],
                            TRANSLATIONS['col_verification'],
                        ])
                        for finding in self.all_findings:
                            writer.writerow(finding)

                elif fmt == "XML":
                    root = ET.Element("results")
                    for finding in self.all_findings:
                        item = ET.SubElement(root, "finding")
                        ET.SubElement(item, "type").text = finding[0]
                        ET.SubElement(item, "source").text = finding[1]
                        ET.SubElement(item, "pattern").text = finding[2]
                        ET.SubElement(item, "url").text = finding[3]
                        ET.SubElement(item, "match").text = finding[4]
                        ET.SubElement(item, "status").text = finding[5]
                        ET.SubElement(item, "verification").text = finding[6]

                    tree = ET.ElementTree(root)
                    tree.write(filepath, encoding='utf-8', xml_declaration=True)

                messagebox.showinfo(TRANSLATIONS['success'], f"{TRANSLATIONS['results_saved_to']}\n{filepath}")

            except Exception as e:
                messagebox.showerror(TRANSLATIONS['error'], f"{TRANSLATIONS['failed_to_save_results']}{str(e)}")

        ttk.Button(format_dialog, text=TRANSLATIONS['save'], command=do_save).pack(pady=10)

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
                messagebox.showinfo(TRANSLATIONS['info'], f"{TRANSLATIONS['open_results']}:\n{results_dir}")
        else:
            messagebox.showinfo(TRANSLATIONS['info'], f"{TRANSLATIONS['open_results']}:\n{results_dir}")

    # Proxy Management Functions
    def load_proxies_from_file(self):
        file_path = filedialog.askopenfilename(
            title=TRANSLATIONS['load_proxies_title'],
            filetypes=[(TRANSLATIONS['text_files'], "*.txt"), (TRANSLATIONS['all_files'], "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        proxy = line.strip()
                        if proxy and not proxy.startswith('#'):
                            self.add_proxy_to_list(proxy)
                self.log_callback(f"{TRANSLATIONS['loaded_proxies_log']}{file_path}")
            except Exception as e:
                messagebox.showerror(TRANSLATIONS['error'], f"{TRANSLATIONS['failed_to_load_proxies']}{str(e)}")

    def test_all_proxies(self):
        if not self.proxies:
            messagebox.showwarning(TRANSLATIONS['warning'], TRANSLATIONS['no_proxies_to_test'])
            return

        self.log_callback(TRANSLATIONS['testing_x_proxies'].format(count=len(self.proxies)))
        
        def test_thread():
            working = []
            for i, proxy in enumerate(self.proxies):
                if self.scanner and self.scanner.test_proxy(proxy):
                    working.append(proxy)
                    self.root.after(0, lambda p=proxy: self.update_proxy_status(p, TRANSLATIONS['working']))
                else:
                    self.root.after(0, lambda p=proxy: self.update_proxy_status(p, TRANSLATIONS['failed']))
            
            self.root.after(0, lambda: self.log_callback(TRANSLATIONS['proxy_test_complete'].format(working=len(working), total=len(self.proxies))))
        
        threading.Thread(target=test_thread, daemon=True).start()

    def clear_all_proxies(self):
        self.proxies = []
        for item in self.proxy_tree.get_children():
            self.proxy_tree.delete(item)
        self.log_callback(TRANSLATIONS['all_proxies_cleared'])

    def add_proxy_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title(TRANSLATIONS['add_proxy'])
        dialog.geometry("400x120")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text=TRANSLATIONS['enter_proxy_msg']).pack(pady=5)
        proxy_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=proxy_var, width=40).pack(pady=5)

        def add():
            proxy = proxy_var.get().strip()
            if proxy:
                self.add_proxy_to_list(proxy)
                dialog.destroy()

        ttk.Button(dialog, text=TRANSLATIONS['add_btn'], command=add).pack(pady=5)

    def add_proxy_to_list(self, proxy):
        if proxy not in self.proxies:
            self.proxies.append(proxy)
            self.proxy_tree.insert("", tk.END, values=(proxy, TRANSLATIONS['unknown']))

    def test_selected_proxy(self):
        selection = self.proxy_tree.selection()
        if not selection:
            messagebox.showwarning(TRANSLATIONS['warning'], TRANSLATIONS['no_proxy_selected'])
            return

        item = selection[0]
        values = self.proxy_tree.item(item)['values']
        proxy = values[0]

        self.log_callback(f"{TRANSLATIONS['testing_proxy_log']}{proxy}")
        
        def test():
            if self.scanner and self.scanner.test_proxy(proxy):
                self.root.after(0, lambda: self.update_proxy_status(proxy, TRANSLATIONS['working']))
            else:
                self.root.after(0, lambda: self.update_proxy_status(proxy, TRANSLATIONS['failed']))
        
        threading.Thread(target=test, daemon=True).start()

    def delete_selected_proxy(self):
        selection = self.proxy_tree.selection()
        if not selection:
            messagebox.showwarning(TRANSLATIONS['warning'], TRANSLATIONS['no_proxy_selected'])
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