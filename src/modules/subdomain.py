#!/usr/bin/env python3
import asyncio
import aiohttp
import async_timeout
import aiodns
import signal
import sys
import os
from pathlib import Path
from subprocess import PIPE
from urllib.parse import urlparse
from ..utils.logger import Logger

# Configure Go environment and PATH
go_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
if go_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + go_bin

# Global flag for graceful shutdown
SHUTDOWN = False

def handle_shutdown(signum, frame):
    global SHUTDOWN
    SHUTDOWN = True
    logger = Logger(__name__)
    logger.info("\n[!] Shutdown signal received. Stopping enumeration gracefully...")

# Register signal handlers
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

class SubdomainFinder:
    def __init__(self, target: str):
        self.target = target
        self.logger = Logger(__name__)
        self.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        self.resolver = aiodns.DNSResolver(nameservers=self.nameservers)
        self.alive_subdomains = set()
        self.dns_records = {}

    async def run_subfinder(self) -> set:
        """Run subfinder for subdomain discovery"""
        try:
            self.logger.info("[*] Running subfinder...")
            # Log the exact command being executed
            cmd = ["subfinder", "-d", self.target, "-silent"]
            self.logger.debug(f"Executing command: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
                env=os.environ  # Pass current environment with updated PATH
            )
            stdout, stderr = await proc.communicate()

            if stderr:
                stderr_text = stderr.decode().strip()
                self.logger.debug(f"Subfinder stderr: {stderr_text}")
                if "command not found" in stderr_text:
                    self.logger.error("[-] Subfinder not found. Please ensure it's installed correctly (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)")
                    return set()

            results = stdout.decode().strip().splitlines()
            discovered = {line.strip() for line in results if line.strip()}
            self.logger.info(f"[+] Subfinder found {len(discovered)} subdomains")
            return discovered
        except FileNotFoundError:
            self.logger.error("[-] Subfinder not found in PATH")
            self.logger.debug(f"Current PATH: {os.environ.get('PATH')}")
        except Exception as e:
            self.logger.error(f"[-] Subfinder error: {str(e)}")
        return set()

    async def run_assetfinder(self) -> set:
        """Run assetfinder for subdomain discovery"""
        try:
            self.logger.info("[*] Running assetfinder...")
            # Log the exact command being executed
            cmd = ["assetfinder", "--subs-only", self.target]
            self.logger.debug(f"Executing command: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
                env=os.environ  # Pass current environment with updated PATH
            )
            stdout, stderr = await proc.communicate()

            if stderr:
                stderr_text = stderr.decode().strip()
                self.logger.debug(f"Assetfinder stderr: {stderr_text}")
                if "command not found" in stderr_text:
                    self.logger.error("[-] Assetfinder not found. Please ensure it's installed correctly (go install -v github.com/tomnomnom/assetfinder@latest)")
                    return set()

            results = stdout.decode().strip().splitlines()
            discovered = {line.strip() for line in results if line.strip() and self.target in line}
            self.logger.info(f"[+] Assetfinder found {len(discovered)} subdomains")
            return discovered
        except FileNotFoundError:
            self.logger.error("[-] Assetfinder not found in PATH")
            self.logger.debug(f"Current PATH: {os.environ.get('PATH')}")
        except Exception as e:
            self.logger.error(f"[-] Assetfinder error: {str(e)}")
        return set()

    async def check_dns(self, subdomain: str) -> bool:
        """Check DNS resolution"""
        try:
            async with async_timeout.timeout(3):
                result = await self.resolver.query(subdomain, 'A')
                if result:
                    self.logger.debug(f"[DNS] {subdomain} resolved successfully")
                    return True
        except Exception as e:
            self.logger.debug(f"[DNS] Failed to resolve {subdomain}: {str(e)}")
        return False

    async def is_alive(self, subdomain: str) -> bool:
        """Check if subdomain is responding to HTTP/HTTPS"""
        if not await self.check_dns(subdomain):
            return False

        for proto in ['https', 'http']:
            url = f"{proto}://{subdomain}"
            try:
                timeout = aiohttp.ClientTimeout(total=5, connect=2)
                connector = aiohttp.TCPConnector(ssl=False, verify_ssl=False)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status < 400:
                            self.logger.info(f"[+] Found alive: {subdomain} ({proto})")
                            return True
            except aiohttp.ClientError as e:
                self.logger.debug(f"[HTTP] Connection failed for {url}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"[HTTP] Error checking {url}: {str(e)}")
        return False

    async def verify_subdomains(self, subdomains: set) -> set:
        """Verify discovered subdomains"""
        sem = asyncio.Semaphore(10)  # Limit concurrent checks
        verified = set()

        async def verify(sub):
            if SHUTDOWN:
                return
            async with sem:
                try:
                    if await self.is_alive(sub):
                        verified.add(sub)
                        self.alive_subdomains.add(sub)
                except Exception as e:
                    self.logger.error(f"Error verifying {sub}: {str(e)}")

        self.logger.info(f"\n[*] Verifying {len(subdomains)} discovered subdomains...")
        await asyncio.gather(*(verify(sub) for sub in subdomains))
        return verified

    async def enumerate(self) -> set:
        """Main enumeration entry point"""
        try:
            # Run tools in parallel
            subfinder_results, assetfinder_results = await asyncio.gather(
                self.run_subfinder(),
                self.run_assetfinder()
            )

            # Combine and deduplicate results
            all_subdomains = subfinder_results.union(assetfinder_results)

            if not all_subdomains:
                self.logger.warning("[-] No subdomains found by tools")
                return set()

            self.logger.info(f"\n[+] Total unique subdomains discovered: {len(all_subdomains)}")

            if SHUTDOWN:
                self.logger.info("[!] Shutdown requested. Stopping enumeration.")
                return set()

            # Verify discovered subdomains
            alive_subdomains = await self.verify_subdomains(all_subdomains)

            self.logger.info(f"\n[+] Summary:")
            self.logger.info(f"    - Total discovered: {len(all_subdomains)}")
            self.logger.info(f"    - Alive subdomains: {len(alive_subdomains)}")

            return alive_subdomains

        except Exception as e:
            self.logger.error(f"[-] Error during enumeration: {str(e)}")
            return set()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomain.py <target-domain>")
        sys.exit(1)

    target = sys.argv[1].strip()
    logger = Logger(__name__)

    try:
        alive_subs = asyncio.run(SubdomainFinder(target).enumerate())
        if alive_subs:
            print("\nAlive subdomains:")
            for sub in sorted(alive_subs):
                print(sub)
    except KeyboardInterrupt:
        logger.info("\n[!] User interrupted the operation")
    except Exception as e:
        logger.error(f"\n[-] Fatal error: {str(e)}")