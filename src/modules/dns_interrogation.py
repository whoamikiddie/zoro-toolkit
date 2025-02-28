from ..utils.dns_resolver import DNSResolver
from ..utils.logger import Logger
import concurrent.futures

class DNSInterrogator:
    def __init__(self):
        self.resolver = DNSResolver()
        self.logger = Logger(__name__)

    def get_all_records(self, domain):
        self.logger.info(f"Starting DNS interrogation for {domain}")

        # Get all DNS records in parallel using async resolver
        results = self.resolver.resolve_all(domain)

        # Perform reverse DNS lookup for A records in parallel
        if 'A' in results:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                reverse_lookups = {
                    ip: future for ip, future in 
                    ((ip, executor.submit(self.resolver.reverse_lookup, ip)) 
                     for ip in results['A'])
                }

                reverse_dns = {
                    ip: future.result() for ip, future in reverse_lookups.items()
                }

            results['REVERSE_DNS'] = reverse_dns

        self.logger.info(f"Completed DNS interrogation for {domain}")
        return results