import aiohttp
import asyncio
import ssl
from ..utils.logger import Logger
from ..utils.http_requester import HTTPRequester
import hashlib
from urllib.parse import urljoin

class TechPrinter:
    def __init__(self):
        self.logger = Logger(__name__)
        self.requester = HTTPRequester()
        self.load_tech_signatures()

    def load_tech_signatures(self):
        """Load technology signatures from predefined patterns"""
        self.signatures = {
            'frameworks': {
                'Django': {
                    'headers': ['X-Django-Version', 'csrftoken'],
                    'body': ['django-debug-toolbar', '__admin__'],
                    'meta': ['name="generator" content="Django']
                },
                'Flask': {
                    'headers': ['Flask'],
                    'cookies': ['session'],
                    'body': ['flask.pocoo.org', 'Werkzeug']
                },
                'Laravel': {
                    'headers': ['Laravel'],
                    'cookies': ['laravel_session'],
                    'body': ['Laravel', 'Illuminate\\']
                },
                'Express.js': {
                    'headers': ['X-Powered-By: Express'],
                    'body': ['express', 'node_modules']
                }
            },
            'cms': {
                'WordPress': {
                    'headers': ['X-Powered-By: WordPress'],
                    'meta': ['name="generator" content="WordPress'],
                    'body': ['/wp-content/', '/wp-includes/'],
                    'paths': ['/wp-admin/', '/wp-login.php']
                },
                'Drupal': {
                    'headers': ['X-Generator: Drupal'],
                    'cookies': ['DRUPAL_'],
                    'body': ['Drupal.settings', 'jquery.once.js']
                }
            },
            'servers': {
                'Nginx': {
                    'headers': ['Server: nginx'],
                    'body': ['nginx']
                },
                'Apache': {
                    'headers': ['Server: Apache'],
                    'body': ['apache']
                },
                'IIS': {
                    'headers': ['Server: Microsoft-IIS'],
                    'body': ['IIS']
                }
            },
            'security': {
                'Cloudflare': {
                    'headers': ['cf-ray', '__cfduid', 'Server: cloudflare'],
                    'body': ['cloudflare-nginx']
                },
                'ModSecurity': {
                    'headers': ['ModSecurity', 'OWASP_CRS'],
                    'body': ['mod_security', 'blocked by mod_security']
                }
            },
            'analytics': {
                'Google Analytics': {
                    'body': ['google-analytics.com/analytics.js', 'ga(\'create\'']
                },
                'Hotjar': {
                    'body': ['hotjar.com', 'hjSetting']
                }
            }
        }

    async def analyze_response(self, url, response, html_content):
        """Analyze response for technology fingerprints"""
        technologies = {}
        headers = dict(response.headers)
        cookies = dict(response.cookies)

        # Convert HTML content to lowercase for case-insensitive matching
        html_lower = html_content.lower()

        for category, tech_dict in self.signatures.items():
            technologies[category] = []
            for tech_name, patterns in tech_dict.items():
                matches = []

                # Check headers
                if 'headers' in patterns:
                    for pattern in patterns['headers']:
                        pattern_lower = pattern.lower()
                        for header, value in headers.items():
                            if pattern_lower in f"{header}: {value}".lower():
                                matches.append(f"Header: {header}")

                # Check cookies
                if 'cookies' in patterns:
                    for pattern in patterns['cookies']:
                        pattern_lower = pattern.lower()
                        for cookie in cookies:
                            if pattern_lower in str(cookie).lower():
                                matches.append(f"Cookie: {cookie}")

                # Check body content
                if 'body' in patterns:
                    for pattern in patterns['body']:
                        pattern_lower = pattern.lower()
                        if pattern_lower in html_lower:
                            matches.append(f"Body: {pattern}")

                # Check meta tags
                if 'meta' in patterns:
                    for pattern in patterns['meta']:
                        pattern_lower = pattern.lower()
                        if pattern_lower in html_lower:
                            matches.append(f"Meta: {pattern}")

                # Check specific paths if available
                if 'paths' in patterns:
                    async with aiohttp.ClientSession() as session:
                        for path in patterns['paths']:
                            try:
                                test_url = urljoin(url, path)
                                async with session.get(test_url, timeout=5, ssl=False) as path_response:
                                    if path_response.status < 400:
                                        matches.append(f"Path: {path}")
                            except:
                                continue

                if matches:
                    technologies[category].append({
                        'name': tech_name,
                        'confidence': len(matches) * 25,  # Simple confidence calculation
                        'evidence': matches
                    })

        # Remove empty categories
        return {k: v for k, v in technologies.items() if v}

    async def fetch_and_analyze(self, url):
        """Fetch URL content and analyze technologies"""
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(url) as response:
                    html_content = await response.text()
                    tech_info = await self.analyze_response(url, response, html_content)

                    if tech_info:
                        self.logger.info({
                            'action': 'technology_detection',
                            'url': url,
                            'technologies': tech_info
                        })

                    return tech_info

        except Exception as e:
            self.logger.error({
                'action': 'tech_detection_error',
                'url': url,
                'error': str(e)
            })
            return {}

    async def analyze_url(self, url):
        """Main entry point for technology analysis"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        return await self.fetch_and_analyze(url)

    def analyze(self, url):
        """Synchronous wrapper for technology analysis"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.analyze_url(url))
        finally:
            loop.close()