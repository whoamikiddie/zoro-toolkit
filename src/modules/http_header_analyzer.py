from ..utils.http_requester import HTTPRequester
from ..utils.logger import Logger
import aiohttp
import async_timeout
from colorama import Fore, Style

class HTTPHeaderAnalyzer:
    def __init__(self):
        self.requester = HTTPRequester()
        self.logger = Logger(__name__)

        # Define critical security headers and their importance weights
        self.security_headers = {
            'X-Frame-Options': {'weight': 10, 'description': 'Prevents clickjacking attacks'},
            'X-XSS-Protection': {'weight': 8, 'description': 'Prevents XSS attacks'},
            'X-Content-Type-Options': {'weight': 7, 'description': 'Prevents MIME-type sniffing'},
            'Strict-Transport-Security': {'weight': 10, 'description': 'Enforces HTTPS'},
            'Content-Security-Policy': {'weight': 9, 'description': 'Prevents various attacks'},
            'Referrer-Policy': {'weight': 6, 'description': 'Controls referrer information'},
            'Permissions-Policy': {'weight': 7, 'description': 'Controls browser features'},
            'Cross-Origin-Opener-Policy': {'weight': 6, 'description': 'Isolates window.opener'},
        }

    async def async_analyze(self, domain):
        self.logger.info(f"Analyzing HTTP headers for {domain}")

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
                            security_analysis = self.analyze_security_headers(headers)
                            cookies_analysis = await self.analyze_cookies(response.cookies)
                            server_info = self.analyze_server_info(headers)

                            # Calculate security score
                            score = self.calculate_security_score(security_analysis)
                            risk_level = self.get_risk_level(score)

                            self.log_security_findings(domain, security_analysis, score, risk_level)

                            results[url] = {
                                'security_headers': security_analysis,
                                'security_score': score,
                                'risk_level': risk_level,
                                'cookies': cookies_analysis,
                                'server_info': server_info,
                                'all_headers': headers
                            }
                except Exception as e:
                    self.logger.error(f"Error analyzing headers for {url}: {str(e)}")

        return results

    def analyze_security_headers(self, headers):
        """Analyze security headers with detailed information"""
        analysis = {}
        for header, info in self.security_headers.items():
            value = headers.get(header, 'Not Set')
            analysis[header] = {
                'value': value,
                'status': 'Set' if value != 'Not Set' else 'Missing',
                'description': info['description'],
                'weight': info['weight']
            }
        return analysis

    async def analyze_cookies(self, cookies):
        """Analyze cookies for security attributes"""
        cookie_analysis = {}
        for cookie in cookies:
            secure = 'secure' in cookie
            httponly = 'httponly' in cookie
            samesite = cookie.get('samesite', 'Not Set')

            security_level = 'High' if secure and httponly and samesite in ['Strict', 'Lax'] else \
                           'Medium' if secure and (httponly or samesite in ['Strict', 'Lax']) else \
                           'Low'

            cookie_analysis[cookie.key] = {
                'secure': secure,
                'httponly': httponly,
                'samesite': samesite,
                'domain': cookie.get('domain', 'Not Set'),
                'path': cookie.get('path', '/'),
                'security_level': security_level
            }
        return cookie_analysis

    def analyze_server_info(self, headers):
        """Analyze server information from headers"""
        server_info = {
            'server': headers.get('Server', 'Not Disclosed'),
            'x_powered_by': headers.get('X-Powered-By', 'Not Disclosed'),
            'x_aspnet_version': headers.get('X-AspNet-Version', 'Not Disclosed'),
            'x_runtime': headers.get('X-Runtime', 'Not Disclosed')
        }

        # Check for information disclosure
        risk_level = 'Low'
        if any(v != 'Not Disclosed' for v in server_info.values()):
            risk_level = 'Medium'
            if any(v and v.lower() != 'not disclosed' and ('/' in v or ' ' in v) 
                  for v in server_info.values()):
                risk_level = 'High'

        server_info['risk_level'] = risk_level
        return server_info

    def calculate_security_score(self, security_analysis):
        """Calculate security score based on headers"""
        total_weight = sum(info['weight'] for info in self.security_headers.values())
        earned_points = sum(info['weight'] for header, info in self.security_headers.items()
                          if security_analysis[header]['status'] == 'Set')
        return round((earned_points / total_weight) * 100)

    def get_risk_level(self, score):
        """Determine risk level based on security score"""
        if score >= 80:
            return {'level': 'Low', 'color': Fore.GREEN}
        elif score >= 60:
            return {'level': 'Medium', 'color': Fore.YELLOW}
        else:
            return {'level': 'High', 'color': Fore.RED}

    def log_security_findings(self, domain, security_analysis, score, risk_level):
        """Log security findings in a structured format"""
        self.logger.info(f"\n{Fore.CYAN}[*] Security Analysis for {domain}{Style.RESET_ALL}")
        self.logger.info(f"Security Score: {risk_level['color']}{score}% ({risk_level['level']} Risk){Style.RESET_ALL}")

        missing_headers = [
            f"{header} ({info['description']})"
            for header, info in security_analysis.items()
            if info['status'] == 'Missing'
        ]

        if missing_headers:
            self.logger.warning(
                f"Missing Critical Headers:\n" + 
                "\n".join(f"  - {header}" for header in missing_headers)
            )

    # Keep synchronous version for backward compatibility
    def analyze(self, domain):
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.async_analyze(domain))
        finally:
            loop.close()