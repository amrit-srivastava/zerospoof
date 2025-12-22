"""
DNS Resolver Service

Robust DNS resolution with:
- EDNS0 support for larger UDP packets
- Automatic TCP fallback for truncated responses
- Configurable timeouts
- Error handling and logging
"""

import dns.resolver
import dns.rdatatype
import dns.exception
import dns.flags
from typing import Optional, List, Tuple
import logging

from scanner.constants import DNS_TIMEOUT, DNS_LIFETIME

logger = logging.getLogger(__name__)


class DNSResolver:
    """
    A robust DNS resolver wrapper around dnspython.
    Handles EDNS0, TCP fallback, and common error cases.
    """
    
    def __init__(self, timeout: float = DNS_TIMEOUT, lifetime: float = DNS_LIFETIME):
        self.timeout = timeout
        self.lifetime = lifetime
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime
        # Use reliable public DNS servers
        self._resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        # Enable EDNS0 for larger UDP responses
        self._resolver.use_edns(edns=0, ednsflags=0, payload=4096)
    
    def _query(
        self, 
        domain: str, 
        rdtype: str,
        raise_on_nxdomain: bool = False
    ) -> Optional[dns.resolver.Answer]:
        """
        Internal query method with TCP fallback.
        
        Args:
            domain: The domain to query
            rdtype: Record type (MX, TXT, A, CNAME, etc.)
            raise_on_nxdomain: If True, raises exception on NXDOMAIN
            
        Returns:
            dns.resolver.Answer or None if not found
        """
        try:
            # First try UDP
            answer = self._resolver.resolve(domain, rdtype)
            return answer
        except dns.resolver.NoAnswer:
            logger.debug(f"No {rdtype} record for {domain}")
            return None
        except dns.resolver.NXDOMAIN:
            if raise_on_nxdomain:
                raise
            logger.debug(f"Domain {domain} does not exist")
            return None
        except dns.resolver.NoNameservers:
            logger.warning(f"No nameservers available for {domain}")
            return None
        except dns.exception.Timeout:
            logger.warning(f"DNS timeout for {domain} {rdtype}")
            return None
        except dns.resolver.YXDOMAIN:
            logger.warning(f"YXDOMAIN for {domain}")
            return None
        except Exception as e:
            logger.error(f"DNS query error for {domain} {rdtype}: {e}")
            return None
    
    def resolve_mx(self, domain: str) -> List[Tuple[int, str]]:
        """
        Resolve MX records for a domain.
        
        Returns:
            List of (priority, hostname) tuples, sorted by priority
        """
        answer = self._query(domain, 'MX')
        if not answer:
            return []
        
        records = []
        for rdata in answer:
            priority = rdata.preference
            host = str(rdata.exchange).rstrip('.')
            records.append((priority, host))
        
        return sorted(records, key=lambda x: x[0])
    
    def resolve_txt(self, domain: str) -> List[str]:
        """
        Resolve TXT records for a domain.
        
        Returns:
            List of TXT record strings (concatenated if multi-part)
        """
        answer = self._query(domain, 'TXT')
        if not answer:
            return []
        
        records = []
        for rdata in answer:
            # TXT records can be split into multiple strings
            txt_value = ''.join(
                part.decode('utf-8') if isinstance(part, bytes) else part 
                for part in rdata.strings
            )
            records.append(txt_value)
        
        return records
    
    def resolve_a(self, domain: str) -> List[str]:
        """
        Resolve A records for a domain.
        
        Returns:
            List of IPv4 addresses
        """
        answer = self._query(domain, 'A')
        if not answer:
            return []
        
        return [str(rdata) for rdata in answer]
    
    def resolve_aaaa(self, domain: str) -> List[str]:
        """
        Resolve AAAA records for a domain.
        
        Returns:
            List of IPv6 addresses
        """
        answer = self._query(domain, 'AAAA')
        if not answer:
            return []
        
        return [str(rdata) for rdata in answer]
    
    def resolve_cname(self, domain: str) -> Optional[str]:
        """
        Resolve CNAME record for a domain.
        
        Returns:
            The canonical name or None
        """
        answer = self._query(domain, 'CNAME')
        if not answer:
            return None
        
        # CNAME should have only one record
        for rdata in answer:
            return str(rdata.target).rstrip('.')
        return None
    
    def host_exists(self, hostname: str) -> bool:
        """
        Check if a hostname resolves to any A or AAAA record.
        
        Returns:
            True if the host resolves, False otherwise
        """
        a_records = self.resolve_a(hostname)
        if a_records:
            return True
        
        aaaa_records = self.resolve_aaaa(hostname)
        return len(aaaa_records) > 0
    
    def get_spf_record(self, domain: str) -> Optional[str]:
        """
        Get the SPF record for a domain.
        
        Returns:
            The SPF record string or None
        """
        txt_records = self.resolve_txt(domain)
        for record in txt_records:
            if record.lower().startswith('v=spf1'):
                return record
        return None
    
    def get_dmarc_record(self, domain: str) -> Tuple[Optional[str], List[str]]:
        """
        Get the DMARC record for a domain.
        
        Returns:
            Tuple of (primary DMARC record, list of all DMARC records found)
            Multiple DMARC records indicate a misconfiguration
        """
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = self.resolve_txt(dmarc_domain)
        
        dmarc_records = [
            record for record in txt_records 
            if record.lower().startswith('v=dmarc1')
        ]
        
        if not dmarc_records:
            return None, []
        
        return dmarc_records[0], dmarc_records
    
    def get_dkim_record(self, domain: str, selector: str) -> Optional[str]:
        """
        Get the DKIM record for a domain and selector.
        
        Args:
            domain: The domain to check
            selector: The DKIM selector
            
        Returns:
            The DKIM record string or None
        """
        dkim_domain = f"{selector}._domainkey.{domain}"
        
        # First check for CNAME
        cname = self.resolve_cname(dkim_domain)
        if cname:
            # Follow the CNAME
            txt_records = self.resolve_txt(cname)
        else:
            txt_records = self.resolve_txt(dkim_domain)
        
        for record in txt_records:
            if 'v=dkim1' in record.lower() or 'k=' in record.lower() or 'p=' in record.lower():
                return record
        
        return None
    
    def get_dkim_cname(self, domain: str, selector: str) -> Optional[str]:
        """
        Get the CNAME target for a DKIM selector.
        Used for M365 validation.
        
        Args:
            domain: The domain to check
            selector: The DKIM selector
            
        Returns:
            The CNAME target or None
        """
        dkim_domain = f"{selector}._domainkey.{domain}"
        return self.resolve_cname(dkim_domain)


# Thread-local storage for resolver instances
import threading
_thread_local = threading.local()

def get_resolver() -> DNSResolver:
    """
    Get a DNS resolver instance.
    Uses thread-local storage for thread safety in concurrent contexts.
    """
    if not hasattr(_thread_local, 'resolver'):
        _thread_local.resolver = DNSResolver()
    return _thread_local.resolver
