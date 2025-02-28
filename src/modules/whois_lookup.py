import whois
from ..utils.logger import Logger

class WhoisLookup:
    def __init__(self):
        self.logger = Logger(__name__)
    
    def lookup(self, domain):
        try:
            self.logger.info(f"Performing WHOIS lookup for {domain}")
            w = whois.whois(domain)
            
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
            }
        except Exception as e:
            self.logger.error(f"WHOIS lookup error for {domain}: {str(e)}")
            return None
