import json
import os
from datetime import datetime
from .logger import Logger
from rich.console import Console

class OutputManager:
    def __init__(self, domain):
        self.logger = Logger(__name__)
        self.domain = domain
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.console = Console()

        # Create session-specific output directory
        self.base_dir = "reports/domain"
        self.session_dir = f"{self.base_dir}/{self.domain}/{self.timestamp}"
        self.create_output_directory()

    def create_output_directory(self):
        """Create organized directory structure for outputs"""
        directories = [
            f"{self.session_dir}/json",
            f"{self.session_dir}/text",
            f"{self.session_dir}/logs"
        ]

        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def save_json(self, data, filename):
        """Save JSON data with proper formatting and error handling"""
        try:
            filepath = os.path.join(self.session_dir, "json", f"{filename}.json")

            # Only write if file doesn't exist or content is different
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=4, sort_keys=True)
                self.console.print(f"[green]✓[/green] Results saved to: [cyan]{filepath}[/cyan]")
            else:
                # Check if content is different before overwriting
                with open(filepath, 'r') as f:
                    existing_data = json.load(f)
                if json.dumps(existing_data, sort_keys=True) != json.dumps(data, sort_keys=True):
                    with open(filepath, 'w') as f:
                        json.dump(data, f, indent=4, sort_keys=True)
                    self.console.print(f"[green]✓[/green] Results updated in: [cyan]{filepath}[/cyan]")

            return filepath
        except Exception as e:
            self.logger.error({
                'action': 'save_json_error',
                'filename': filename,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            return None

    def save_text(self, data, filename):
        """Save text data with proper formatting and error handling"""
        try:
            filepath = os.path.join(self.session_dir, "text", f"{filename}.txt")

            # Only write if file doesn't exist or content is different
            if not os.path.exists(filepath) or self._is_content_different(filepath, data):
                with open(filepath, 'w') as f:
                    f.write(data)
                self.console.print(f"[green]✓[/green] Results saved to: [cyan]{filepath}[/cyan]")

            return filepath
        except Exception as e:
            self.logger.error({
                'action': 'save_text_error',
                'filename': filename,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            return None

    def save_log(self, data, filename):
        """Save log data with timestamp and proper formatting"""
        try:
            filepath = os.path.join(self.session_dir, "logs", f"{filename}.log")
            log_entry = f"# Log generated at {datetime.now().isoformat()}\n\n{data}"

            # Append to existing log file or create new one
            mode = 'a' if os.path.exists(filepath) else 'w'
            with open(filepath, mode) as f:
                f.write(log_entry + "\n")

            return filepath
        except Exception as e:
            self.logger.error({
                'action': 'save_log_error',
                'filename': filename,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            return None

    def _is_content_different(self, filepath, new_content):
        """Check if new content is different from existing file content"""
        try:
            with open(filepath, 'r') as f:
                existing_content = f.read()
            return existing_content != new_content
        except:
            return True

    def create_summary(self, results):
        """Create a summary of all findings"""
        summary = {
            "timestamp": self.timestamp,
            "domain": self.domain,
            "statistics": {
                "total_subdomains": len(results.get('subdomains', [])),
                "dns_records": len(results.get('dns', {}).get('A', [])),
                "waf_detections": sum(1 for _, data in results.get('subdomain_analysis', {}).items() 
                                    if data.get('waf') and any(waf.get('detected_wafs', []) 
                                    for waf in data['waf'].values()))
            },
            "files": {
                "json_dir": os.path.join(self.session_dir, "json"),
                "text_dir": os.path.join(self.session_dir, "text"),
                "logs_dir": os.path.join(self.session_dir, "logs")
            }
        }

        return self.save_json(summary, "summary")