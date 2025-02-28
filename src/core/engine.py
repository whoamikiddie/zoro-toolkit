import asyncio
import concurrent.futures
from datetime import datetime
from ..utils.banner import Banner
import time
from ..modules.dns_interrogation import DNSInterrogator
from ..modules.whois_lookup import WhoisLookup
from ..modules.subdomain import SubdomainFinder
from ..modules.web_server_fingerprinter import WebServerFingerprinter
from ..modules.http_header_analyzer import HTTPHeaderAnalyzer
from ..modules.waf_detector import WAFDetector
from ..modules.tech_print import TechPrinter
from ..utils.output_manager import OutputManager
from ..utils.logger import Logger
from rich.progress import Progress, SpinnerColumn, TextColumn
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

class Engine:
    def __init__(self, domain, workers=None):
        self.domain = domain
        self.logger = Logger(__name__)
        self.output_manager = OutputManager(domain)
        self.banner = Banner()

        # Set number of workers
        self.workers = workers or min(4, multiprocessing.cpu_count())

        # Initialize modules
        self.dns_interrogator = DNSInterrogator()
        self.whois_lookup = WhoisLookup()
        self.subdomain_finder = SubdomainFinder(domain)  # Updated to use new SubdomainFinder
        self.web_fingerprinter = WebServerFingerprinter()
        self.header_analyzer = HTTPHeaderAnalyzer()
        self.waf_detector = WAFDetector()
        self.tech_printer = TechPrinter()

    def run(self):
        """Execute reconnaissance with enhanced subdomain enumeration"""
        self.banner.show_banner()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.banner.console,
            transient=True
        ) as progress:
            recon_task = progress.add_task("Starting reconnaissance...", total=None)
            self.logger.info({'action': 'recon_start', 'domain': self.domain})

            results = {}
            start_time = datetime.now()

            try:
                # DNS and WHOIS Analysis (parallel)
                progress.update(recon_task, description="Gathering DNS and WHOIS information...")
                with ThreadPoolExecutor(max_workers=2) as executor:
                    future_dns = executor.submit(self.dns_interrogator.get_all_records, self.domain)
                    future_whois = executor.submit(self.whois_lookup.lookup, self.domain)

                    results['dns'] = future_dns.result()
                    results['whois'] = future_whois.result()

                    self.output_manager.save_json(results['dns'], 'dns_records')
                    self.output_manager.save_json(results['whois'], 'whois_info')

                # Log DNS findings
                if results['dns'].get('A'):
                    for record in results['dns']['A']:
                        self.logger.info({'dns': f"A → {record}"})

                # Enhanced Subdomain Enumeration using new SubdomainFinder
                progress.update(recon_task, description="Enumerating subdomains...")
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    results['subdomains'] = loop.run_until_complete(self.subdomain_finder.enumerate())
                finally:
                    loop.close()

                if results['subdomains']:
                    progress.update(recon_task, description="Analyzing discovered subdomains...")

                    # Save subdomain results immediately
                    self.output_manager.save_json({
                        'total_discovered': len(results['subdomains']),
                        'alive_subdomains': len(self.subdomain_finder.alive_subdomains),
                        'subdomains': sorted(list(results['subdomains']))
                    }, 'subdomain_results')

                # Save complete analysis
                progress.update(recon_task, description="Saving results...")
                self.output_manager.save_json(results, 'complete_analysis')

                # Calculate statistics
                duration = (datetime.now() - start_time).total_seconds()
                waf_count = sum(1 for subdomain in results.get('subdomains', [])
                              if self.waf_detector.detect(subdomain))

                tech_count = sum(1 for subdomain in results.get('subdomains', [])
                               if self.tech_printer.analyze(subdomain))

                # Create summary for display
                summary_data = {
                    "Target Domain": self.domain,
                    "Duration": f"{duration:.2f} seconds",
                    "Total Subdomains": len(results.get('subdomains', [])),
                    "Alive Subdomains": len(self.subdomain_finder.alive_subdomains),
                    "DNS Records": len(results.get('dns', {}).get('A', [])),
                    "WAF Protected": waf_count,
                    "Technologies Detected": tech_count
                }

                progress.update(recon_task, description="Completed!")
                self.banner.show_summary_table(summary_data)

            except Exception as e:
                self.logger.error({
                    'error': f"Reconnaissance failed: {str(e)}"
                })

            return results