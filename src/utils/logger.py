import logging
import os
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from colorama import init, Fore, Style

class Logger:
    _instance = None
    _lock = None

    def __new__(cls, name="zoro_toolkit"):
        if cls._instance is None:
            from threading import Lock
            cls._lock = Lock()
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(Logger, cls).__new__(cls)
                    cls._instance._initialize(name)
        return cls._instance

    def _initialize(self, name):
        """Initialize the logger with proper handlers and formatters"""
        init()  # Initialize colorama
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []

        # Setup log directory
        log_dir = "reports/logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Use a single log file for the session
        log_file = f"{log_dir}/zoro.log"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())

        # Console handler for clean output
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(ReconFormatter())

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _format_message(self, level, message):
        """Format message with minimal necessary context"""
        if isinstance(message, dict):
            message.update({'timestamp': datetime.now().isoformat()})
            return message
        return {'message': str(message), 'timestamp': datetime.now().isoformat()}

    def info(self, message):
        """Log info message"""
        self.logger.info(self._format_message('INFO', message))

    def success(self, message):
        """Log success message"""
        self.logger.info(self._format_message('SUCCESS', message))

    def error(self, message):
        """Log error message"""
        self.logger.error(self._format_message('ERROR', message))

    def warning(self, message):
        """Log warning message"""
        self.logger.warning(self._format_message('WARNING', message))

    def debug(self, message):
        """Log debug message"""
        self.logger.debug(self._format_message('DEBUG', message))

class JsonFormatter(logging.Formatter):
    """JSON formatter for file logs"""
    def format(self, record):
        if isinstance(record.msg, dict):
            data = record.msg
        else:
            data = {
                'message': str(record.msg),
                'timestamp': datetime.now().isoformat()
            }
        return json.dumps(data)

class ReconFormatter(logging.Formatter):
    """Clean formatter focused on recon output"""
    COLORS = {
        'DNS': Fore.CYAN,
        'WAF': Fore.YELLOW,
        'SUBDOMAIN': Fore.GREEN,
        'VULN': Fore.RED,
        'INFO': Fore.WHITE,
        'ERROR': Fore.RED
    }

    def format(self, record):
        if isinstance(record.msg, dict):
            msg = record.msg

            # Handle different types of recon messages
            if 'subdomain' in msg:
                return f"{Fore.GREEN}[+] Found: {msg['subdomain']}{Style.RESET_ALL}"

            if 'waf_type' in msg:
                return f"{Fore.YELLOW}[WAF] {msg['domain']} → {msg['waf_type']}{Style.RESET_ALL}"

            if 'dns' in msg:
                return f"{Fore.CYAN}[DNS] {msg['dns']}{Style.RESET_ALL}"

            if 'vuln' in msg:
                return f"{Fore.RED}[!] {msg['vuln']}{Style.RESET_ALL}"

            if 'error' in msg:
                return f"{Fore.RED}[-] {msg['error']}{Style.RESET_ALL}"

            # Default structured message
            if 'action' in msg:
                color = self.COLORS.get(msg['action'].split('_')[0].upper(), Fore.WHITE)
                return f"{color}[{msg['action']}] {msg.get('message', '')}{Style.RESET_ALL}"

            return f"{Fore.WHITE}{msg.get('message', str(msg))}{Style.RESET_ALL}"

        # Simple string messages
        return f"{Fore.WHITE}{record.msg}{Style.RESET_ALL}"