"""
DKIM Checker Module

Validates DKIM (DomainKeys Identified Mail) records for a domain.

Scoring (25 points total):
- +5: At least one selector record exists and parses
- +8: Public key length ≥2048 (+8), 1024 (+4), <1024 (+0)
- +8: M365: both selector1 and selector2 CNAME correctly (+8), one (+4)
- +4: Non-M365: two or more selectors discovered (rotation readiness)

Note: V1 validates DNS readiness; it does not verify live DKIM signing.
"""

import base64
import re
from typing import Dict, List, Optional, Tuple

from scanner.checkers.base import BaseChecker, CheckResult
from scanner.services.dns_resolver import get_resolver
from scanner.services.provider_detector import EmailProvider
from scanner.constants import COMMON_DKIM_SELECTORS, M365_DKIM_SELECTORS


class DKIMChecker(BaseChecker):
    """
    DKIM record checker.
    
    Validates:
    1. DKIM selector records exist
    2. Public key strength
    3. M365-specific CNAME configuration
    4. Multiple selector readiness
    """
    
    name = "dkim"
    max_points = 25
    
    # Points breakdown
    POINTS_SELECTOR_EXISTS = 5
    POINTS_KEY_2048 = 8
    POINTS_KEY_1024 = 4
    POINTS_M365_BOTH = 8
    POINTS_M365_ONE = 4
    POINTS_MULTI_SELECTOR = 4
    
    def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Check DKIM records for the domain.
        
        Args:
            domain: The domain to check
            **kwargs: Should include 'provider' (EmailProvider)
            
        Returns:
            CheckResult with DKIM validation results
        """
        result = self._create_result()
        resolver = get_resolver()
        
        provider = kwargs.get("provider", EmailProvider.UNKNOWN)
        is_m365 = provider == EmailProvider.MICROSOFT_365
        
        result.parsed_data["provider"] = provider.value
        result.parsed_data["is_m365"] = is_m365
        
        # Discover DKIM selectors
        discovered_selectors = []
        selector_records = {}
        
        # For M365, prioritize M365 selectors
        selectors_to_check = (
            M365_DKIM_SELECTORS if is_m365 
            else COMMON_DKIM_SELECTORS
        )
        
        for selector in selectors_to_check:
            record = resolver.get_dkim_record(domain, selector)
            if record:
                discovered_selectors.append(selector)
                selector_records[selector] = record
                result.raw_records.append(f"{selector}: {record[:100]}...")
        
        result.parsed_data["discovered_selectors"] = discovered_selectors
        result.parsed_data["selector_count"] = len(discovered_selectors)
        
        # Check 1: At least one selector exists
        if discovered_selectors:
            result.points += self.POINTS_SELECTOR_EXISTS
            result.add_message(
                "success", 
                f"Found {len(discovered_selectors)} DKIM selector(s): {', '.join(discovered_selectors)}"
            )
        else:
            result.add_message("error", "No DKIM selectors found")
            result.add_remediation("Configure DKIM signing with your email provider")
            return result
        
        # Check 2: Key length
        max_key_length = 0
        key_lengths = {}
        
        for selector, record in selector_records.items():
            key_length = self._extract_key_length(record)
            key_lengths[selector] = key_length
            if key_length > max_key_length:
                max_key_length = key_length
        
        result.parsed_data["key_lengths"] = key_lengths
        result.parsed_data["max_key_length"] = max_key_length
        
        if max_key_length >= 2048:
            result.points += self.POINTS_KEY_2048
            result.add_message("success", f"DKIM key length: {max_key_length} bits (strong)")
        elif max_key_length >= 1024:
            result.points += self.POINTS_KEY_1024
            result.add_message(
                "warning", 
                f"DKIM key length: {max_key_length} bits (consider upgrading to 2048)"
            )
            result.add_remediation("Upgrade DKIM key to 2048 bits for stronger security")
        elif max_key_length > 0:
            result.add_message(
                "error", 
                f"DKIM key length: {max_key_length} bits (too weak)"
            )
            result.add_remediation("DKIM key is too short. Upgrade to at least 2048 bits")
        else:
            result.add_message("warning", "Could not determine DKIM key length")
        
        # Check 3: M365-specific or multi-selector
        if is_m365:
            # Check M365 CNAME configuration
            m365_selectors_valid = 0
            m365_cnames = {}
            
            for selector in M365_DKIM_SELECTORS:
                cname = resolver.get_dkim_cname(domain, selector)
                if cname and "onmicrosoft.com" in cname.lower():
                    m365_selectors_valid += 1
                    m365_cnames[selector] = cname
            
            result.parsed_data["m365_cnames"] = m365_cnames
            result.parsed_data["m365_selectors_valid"] = m365_selectors_valid
            
            if m365_selectors_valid >= 2:
                result.points += self.POINTS_M365_BOTH
                result.add_message(
                    "success", 
                    "Both M365 DKIM selectors (selector1, selector2) are configured"
                )
            elif m365_selectors_valid == 1:
                result.points += self.POINTS_M365_ONE
                result.add_message(
                    "warning", 
                    "Only one M365 DKIM selector configured"
                )
                result.add_remediation(
                    "Enable both selector1 and selector2 in Microsoft 365 admin"
                )
            else:
                result.add_message(
                    "error", 
                    "M365 DKIM selectors not properly configured"
                )
                result.add_remediation(
                    "Configure DKIM in Microsoft 365 admin center"
                )
        else:
            # Check for multiple selectors (rotation readiness)
            if len(discovered_selectors) >= 2:
                result.points += self.POINTS_MULTI_SELECTOR
                result.add_message(
                    "success", 
                    "Multiple DKIM selectors found (good for key rotation)"
                )
            else:
                result.add_message(
                    "info", 
                    "Single DKIM selector found. Consider adding a second for key rotation"
                )
        
        return result
    
    def _extract_key_length(self, dkim_record: str) -> int:
        """
        Extract the public key length from a DKIM record.
        
        Args:
            dkim_record: The DKIM TXT record
            
        Returns:
            Key length in bits, or 0 if cannot be determined
        """
        # Find the p= tag (public key)
        match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
        if not match:
            return 0
        
        public_key_b64 = match.group(1)
        
        # Empty p= means key is revoked
        if not public_key_b64:
            return 0
        
        try:
            # Decode base64 and calculate key length
            # The key is DER-encoded, rough estimation: bytes * 8 ~= bits
            key_bytes = base64.b64decode(public_key_b64)
            # RSA public key length is roughly (total bytes - overhead) * 8
            # A 2048-bit key is ~270 bytes, 1024-bit is ~162 bytes
            key_length = len(key_bytes) * 8
            
            # Normalize to standard key sizes
            if key_length >= 2000:
                return 2048
            elif key_length >= 1000:
                return 1024
            elif key_length >= 500:
                return 512
            else:
                return key_length
        except Exception:
            return 0
