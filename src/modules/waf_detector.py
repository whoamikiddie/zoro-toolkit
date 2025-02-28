import aiohttp
import async_timeout
import re
from colorama import Fore, Style
from ..utils.http_requester import HTTPRequester
from ..utils.logger import Logger
from datetime import datetime

class WAFDetector:
    def __init__(self):
        self.requester = HTTPRequester()
        self.logger = Logger(__name__)

        # Enhanced WAF signatures with more specific patterns
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare'],
                'cookies': ['__cfduid', 'cf_clearance', '_cfduuid'],
                'body': ['cloudflare-nginx', 'ray-id', 'error code: 1020']
            },
            'AWS WAF': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-id'],
                'cookies': ['awsalb', 'awsalbcors', 'aws-waf'],
                'body': ['aws-waf', 'aws-waf-token', 'x-amzn-ErrorType']
            },
            'Akamai': {
                'headers': ['akamai-origin-hop', 'akamai-server-ip', 'x-akamai'],
                'cookies': ['akacd_', 'akavpau_', 'aka_'],
                'body': ['akamai-error-page', 'access denied']
            },
            'Imperva': {
                'headers': ['x-iinfo', 'x-cdn', 'incap_ses'],
                'cookies': ['incap_ses', '_incap_', 'visid_incap'],
                'body': ['incapsula', 'incap_ses', '_Incapsula_']
            }
        }

    async def async_detect(self, domain):
        """Detect WAF with strict validation"""
        urls = [
            f"http://{domain}",
            f"https://{domain}"
        ]

        results = {}
        async with aiohttp.ClientSession() as session:
            for url in urls:
                try:
                    async with async_timeout.timeout(5):
                        async with session.get(url) as response:
                            headers = dict(response.headers)
                            cookies = dict(response.cookies)
                            body = await response.text()

                            # First check for strong WAF indicators
                            detected_wafs = await self.analyze_response(headers, cookies, body)
                            if detected_wafs:
                                confidence_levels = self.calculate_confidence(detected_wafs, headers, cookies, body)
                                evidence = self.extract_matched_patterns(body)

                                # Only log high-confidence detections (>=80%)
                                for waf, conf in confidence_levels.items():
                                    if conf >= 80:
                                        self.logger.info({
                                            'waf_type': waf,
                                            'domain': domain,
                                            'confidence': conf,
                                            'protocol': url.split('://')[0],
                                            'evidence_count': len(evidence)
                                        })

                                results[url] = {
                                    'detected_wafs': detected_wafs,
                                    'confidence_levels': confidence_levels,
                                    'evidence': {
                                        'headers': [k.lower() for k in headers.keys()],
                                        'cookies': [k.lower() for k in cookies.keys()],
                                        'body_matches': evidence
                                    }
                                }
                except Exception as e:
                    self.logger.error({
                        'action': 'waf_detection_error',
                        'domain': domain,
                        'url': url,
                        'error': str(e)
                    })

        return results

    async def analyze_response(self, headers, cookies, body):
        """Analyze response with strict pattern matching"""
        detected = set()
        headers_str = str(headers).lower()
        cookies_str = str(cookies).lower()
        body_str = body.lower()

        for waf, signatures in self.waf_signatures.items():
            # Headers (40% weight) - require multiple matches
            header_matches = sum(1 for sig in signatures['headers'] 
                               if sig.lower() in headers_str)
            if header_matches >= 2:  # Require at least 2 header matches
                detected.add(waf)
                continue

            # Cookies (30% weight) - require exact matches
            if any(sig.lower() in cookies_str for sig in signatures['cookies']):
                detected.add(waf)
                continue

            # Body patterns (30% weight) - require exact phrase matches
            if any(sig.lower() in body_str and len(sig) > 10 for sig in signatures['body']):
                detected.add(waf)

        return list(detected)

    def calculate_confidence(self, detected_wafs, headers, cookies, body):
        """Calculate confidence with stricter scoring"""
        confidence_levels = {}
        headers_str = str(headers).lower()
        cookies_str = str(cookies).lower()
        body_str = body.lower()

        for waf in detected_wafs:
            signatures = self.waf_signatures[waf]
            score = 0

            # Header matches with increased specificity
            header_matches = sum(1 for sig in signatures['headers']
                               if sig.lower() in headers_str)
            score += (header_matches / len(signatures['headers'])) * 40 if signatures['headers'] else 0

            # Cookie matches (exact matches only)
            cookie_matches = sum(1 for sig in signatures['cookies']
                               if any(sig.lower() == cookie.lower() for cookie in cookies))
            score += (cookie_matches / len(signatures['cookies'])) * 30 if signatures['cookies'] else 0

            # Body matches (require longer patterns)
            body_matches = sum(1 for sig in signatures['body']
                             if sig.lower() in body_str and len(sig) > 10)
            score += (body_matches / len(signatures['body'])) * 30 if signatures['body'] else 0

            # Bonuses for multiple strong indicators
            if header_matches >= 2 and cookie_matches > 0:
                score += 10
            if header_matches >= 2 and body_matches > 0:
                score += 10

            # Penalties for weak matches
            if header_matches == 0 and cookie_matches == 0:
                score -= 20
            if header_matches == 1:  # Single header matches are weak indicators
                score -= 10

            confidence_levels[waf] = min(round(score), 100)

        return confidence_levels

    def extract_matched_patterns(self, body):
        """Extract matched patterns with improved accuracy"""
        matches = []
        body_lower = body.lower()

        # More specific WAF response patterns
        patterns = [
            r'firewall block|blocked by firewall',
            r'security rule|security block',
            r'access denied.*security',
            r'attack.*detected|malicious',
            r'suspicious.*activity',
            r'protection.*enabled'
        ]

        for pattern in patterns:
            if found := re.findall(pattern, body_lower):
                matches.extend(found)

        return list(set(matches))

    # Keep synchronous version for backward compatibility
    def detect(self, domain):
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.async_detect(domain))
        finally:
            loop.close()