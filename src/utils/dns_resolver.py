import dns.resolver
import dns.exception
from dns.resolver import NoAnswer, NXDOMAIN, NoNameservers
import concurrent.futures
import asyncio
import aiodns
from .logger import Logger
from functools import lru_cache
import async_timeout
import json

class DNSResolver:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.logger = Logger(__name__)
        self.config = self.load_config()

        # Set default DNS servers from config
        self.nameservers = self.config['dns_servers']
        self.resolver.nameservers = self.nameservers
        self.resolver.timeout = self.config['threading'].get('dns_timeout', 2)
        self.resolver.lifetime = self.config['threading'].get('dns_timeout', 2)

        # Track consecutive failures for error handling
        self.consecutive_failures = 0
        self.max_consecutive_failures = self.config['error_handling'].get('max_consecutive_failures', 5)
        self.failure_delay = self.config['error_handling'].get('failure_delay', 2)

    def load_config(self):
        try:
            with open("config/config.json", 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            return {
                "dns_servers": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"],
                "threading": {"http_timeout": 10},
                "retry": {"max_retries": 3, "backoff_factor": 1.5},
                "error_handling": {
                    "max_consecutive_failures": 5,
                    "failure_delay": 2,
                    "ignore_ssl_errors": True
                }
            }

    def handle_failure(self):
        """Handle consecutive failures with exponential backoff"""
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.max_consecutive_failures:
            delay = self.failure_delay * (2 ** (self.consecutive_failures - self.max_consecutive_failures))
            self.logger.warning(f"Too many consecutive failures, backing off for {delay} seconds")
            import time
            time.sleep(delay)

    @lru_cache(maxsize=1024)
    def resolve(self, domain, record_type='A'):
        """Resolve DNS records with caching and error handling"""
        try:
            answers = self.resolver.resolve(domain, record_type)
            self.consecutive_failures = 0  # Reset on success
            return [str(rdata) for rdata in answers]
        except (NoAnswer, NXDOMAIN, NoNameservers) as e:
            self.logger.debug(f"No {record_type} records found for {domain}: {str(e)}")
            return []
        except dns.exception.DNSException as e:
            self.handle_failure()
            self.logger.error(f"DNS resolution error for {domain} ({record_type}): {str(e)}")
            return []
        except Exception as e:
            self.handle_failure()
            self.logger.error(f"Unexpected error resolving {domain} ({record_type}): {str(e)}")
            return []

    async def async_resolve(self, resolver, domain, record_type='A'):
        """Asynchronously resolve DNS records with error handling"""
        try:
            async with async_timeout.timeout(self.config['threading'].get('dns_timeout', 2)):
                result = await resolver.query(domain, record_type)
                self.consecutive_failures = 0  # Reset on success
                if record_type in ['A', 'AAAA']:
                    return [r.host for r in result]
                elif record_type == 'MX':
                    return [f"{r.host} (priority: {r.priority})" for r in result]
                elif record_type == 'TXT':
                    return [r.text for r in result]
                return [str(r) for r in result]
        except asyncio.TimeoutError:
            self.handle_failure()
            self.logger.warning(f"Timeout resolving {domain} ({record_type})")
            return []
        except Exception as e:
            self.handle_failure()
            self.logger.debug(f"Async DNS resolution error for {domain} ({record_type}): {str(e)}")
            return []

    async def async_resolve_all(self, domain, record_types):
        """Resolve all DNS record types concurrently with error handling"""
        resolver = aiodns.DNSResolver(nameservers=self.nameservers)
        tasks = [self.async_resolve(resolver, domain, rtype) for rtype in record_types]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {rtype: result for rtype, result in zip(record_types, results) 
                if isinstance(result, list)}

    def resolve_all(self, domain, record_types=None):
        """Resolve all DNS records with proper error handling"""
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

        # Create a new event loop for this resolution
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            results = loop.run_until_complete(
                self.async_resolve_all(domain, record_types)
            )
        except Exception as e:
            self.logger.error(f"Error resolving all records for {domain}: {str(e)}")
            results = {rtype: self.resolve(domain, rtype) for rtype in record_types}
        finally:
            loop.close()

        return results

    @lru_cache(maxsize=1024)
    def reverse_lookup(self, ip):
        """Perform reverse DNS lookup with caching and error handling"""
        try:
            answers = dns.resolver.resolve_address(ip)
            self.consecutive_failures = 0  # Reset on success
            return [str(rdata) for rdata in answers]
        except Exception as e:
            # Don't treat reverse lookup failures as critical errors
            self.logger.debug(f"Reverse DNS lookup error for {ip}: {str(e)}")
            return []