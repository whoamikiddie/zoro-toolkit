from ..utils.http_requester import HTTPRequester
from ..utils.logger import Logger
import asyncio
import aiohttp
import async_timeout

class WebServerFingerprinter:
    def __init__(self):
        self.requester = HTTPRequester()
        self.logger = Logger(__name__)

    async def async_fingerprint(self, domain):
        self.logger.info(f"Starting web server fingerprinting for {domain}")

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
                            results[url] = {
                                'server': response.headers.get('Server', 'Unknown'),
                                'x_powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                                'status_code': response.status,
                                'technologies': await self.detect_technologies(response)
                            }
                except Exception as e:
                    self.logger.error(f"Error fingerprinting {url}: {str(e)}")

        return results

    async def detect_technologies(self, response):
        technologies = []

        # Check headers for common technologies
        headers = response.headers
        if 'PHP' in str(headers):
            technologies.append('PHP')
        if 'ASP.NET' in str(headers):
            technologies.append('ASP.NET')
        if 'JSP' in str(headers):
            technologies.append('JSP')

        # Check response content for common signatures
        try:
            content = await response.text()
            content = content.lower()

            if 'wordpress' in content:
                technologies.append('WordPress')
            if 'drupal' in content:
                technologies.append('Drupal')
            if 'joomla' in content:
                technologies.append('Joomla')
        except:
            pass

        return technologies

    # Keep the synchronous method for backward compatibility
    def fingerprint(self, domain):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.async_fingerprint(domain))
        finally:
            loop.close()