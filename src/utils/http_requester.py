import requests
from requests.exceptions import RequestException
import time
import json
from functools import lru_cache
from .logger import Logger
from .rate_limit import RateLimiter

class HTTPRequester:
    def __init__(self):
        self.logger = Logger(__name__)
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.config = self.load_config()
        # Initialize domain-specific rate limiters
        self.rate_limiters = {}
        self.default_timeout = self.config['threading'].get('http_timeout', 10)
        self.max_retries = self.config['retry'].get('max_retries', 3)
        self.backoff_factor = self.config['retry'].get('backoff_factor', 1.5)

    def load_config(self):
        try:
            with open("config/config.json", 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            return {
                "ssl": {
                    "verify": True,
                    "bypass_verification": False,
                    "verify_hostname": True
                },
                "threading": {"http_timeout": 10},
                "retry": {"max_retries": 3, "backoff_factor": 1.5},
                "rate_limits": {"requests_per_second": 10, "time_window": 1}
            }

    def get_rate_limiter(self, domain):
        """Get or create a rate limiter for a specific domain"""
        if domain not in self.rate_limiters:
            rps = self.config['rate_limits'].get('requests_per_second', 10)
            window = self.config['rate_limits'].get('time_window', 1)
            self.rate_limiters[domain] = RateLimiter(max_requests=rps, time_window=window)
        return self.rate_limiters[domain]

    @lru_cache(maxsize=100)
    def get_cached(self, url, timeout=None):
        """Cached version of the get request"""
        return self.get(url, timeout, use_cache=False)

    def get(self, url, timeout=None, use_cache=True):
        """
        Make an HTTP GET request with retries, rate limiting, and SSL handling
        """
        if use_cache:
            return self.get_cached(url, timeout)

        timeout = timeout or self.default_timeout
        domain = url.split('/')[2]
        rate_limiter = self.get_rate_limiter(domain)
        verify_ssl = self.config['ssl'].get('verify', True)
        verify_hostname = self.config['ssl'].get('verify_hostname', True)

        for attempt in range(self.max_retries + 1):
            try:
                with rate_limiter:
                    # Custom SSL context if hostname verification is disabled
                    if not verify_hostname and verify_ssl:
                        import ssl
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        self.session.verify = ssl_context

                    response = self.session.get(
                        url,
                        timeout=timeout,
                        verify=verify_ssl
                    )
                    response.raise_for_status()
                    return response

            except requests.exceptions.SSLError as e:
                if self.config['ssl'].get('bypass_verification', False):
                    self.logger.warning(f"SSL verification failed for {url}, retrying without verification")
                    verify_ssl = False
                    continue
                self.logger.error(f"SSL error for {url}: {str(e)}")
                return None

            except requests.exceptions.HTTPError as e:
                self.logger.error(f"HTTP {e.response.status_code} error for {url}: {str(e)}")
                if attempt == self.max_retries or e.response.status_code in [401, 403, 404]:
                    return None
                time.sleep(self.backoff_factor * (attempt + 1))

            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout for {url} (attempt {attempt + 1}/{self.max_retries + 1})")
                if attempt == self.max_retries:
                    return None
                time.sleep(self.backoff_factor * (attempt + 1))

            except RequestException as e:
                self.logger.error(f"Request error for {url}: {str(e)}")
                return None

        return None

    def get_headers(self, url, use_cache=True):
        """Get headers from a URL with optional caching"""
        response = self.get(url, use_cache=use_cache)
        if response:
            return dict(response.headers)
        return {}