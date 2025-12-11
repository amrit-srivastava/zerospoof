"""
DMARC Checker Module

Validates DMARC (Domain-based Message Authentication, Reporting & Conformance) records.

Scoring (40 points total):
- +10: DMARC record present & unique (v=DMARC1)
- +15: p=reject (+15), p=quarantine (+10), p=none (+0)
- +5: rua configured with at least one valid mailto: URI
- +5: Strict alignment (adkim=s + aspf=s) (+5), one strict (+3)
- +3: fo includes 1 (or s/d) for detailed failure reports
- +2: pct=100 (+2), pct<100 (+1)
- +2: sp set and aligned with parent policy
"""

import re
from typing import Dict, List, Optional, Tuple

from scanner.checkers.base import BaseChecker, CheckResult
from scanner.services.dns_resolver import get_resolver
from scanner.constants import VALID_DMARC_TAGS


class DMARCChecker(BaseChecker):
    """
    DMARC record checker.
    
    Validates:
    1. DMARC record exists and is unique
    2. Policy strength
    3. Reporting configuration
    4. Alignment settings
    5. Failure reporting options
    6. Percentage and subdomain policy
    """
    
    name = "dmarc"
    max_points = 40
    
    # Points breakdown
    POINTS_EXISTS = 10
    POINTS_REJECT = 15
    POINTS_QUARANTINE = 10
    POINTS_RUA = 5
    POINTS_STRICT_BOTH = 5
    POINTS_STRICT_ONE = 3
    POINTS_FO = 3
    POINTS_PCT_100 = 2
    POINTS_PCT_PARTIAL = 1
    POINTS_SP = 2
    
    def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Check DMARC record for the domain.
        
        Returns:
            CheckResult with DMARC validation results
        """
        result = self._create_result()
        resolver = get_resolver()
        
        # Get DMARC record
        dmarc_record, all_dmarc_records = resolver.get_dmarc_record(domain)
        
        if all_dmarc_records:
            result.raw_records = all_dmarc_records
        
        # Check 1: DMARC record exists and is unique
        if not dmarc_record:
            result.add_message("error", "No DMARC record found")
            result.add_remediation(
                "Add a DMARC record: _dmarc.yourdomain.com TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com\""
            )
            return result
        
        if len(all_dmarc_records) > 1:
            result.add_message(
                "warning", 
                f"Multiple DMARC records found ({len(all_dmarc_records)}) - this may cause issues"
            )
            result.add_remediation("Remove duplicate DMARC records, keep only one")
        else:
            result.points += self.POINTS_EXISTS
            result.add_message("success", "DMARC record found and unique")
        
        # Parse the DMARC record
        parsed = self._parse_dmarc(dmarc_record)
        result.parsed_data = parsed
        
        # Check 2: Policy strength
        policy = parsed.get("p", "").lower()
        
        if policy == "reject":
            result.points += self.POINTS_REJECT
            result.add_message("success", "DMARC policy is 'reject' (strongest)")
        elif policy == "quarantine":
            result.points += self.POINTS_QUARANTINE
            result.add_message(
                "warning", 
                "DMARC policy is 'quarantine' - consider upgrading to 'reject'"
            )
            result.add_remediation("Upgrade DMARC policy from p=quarantine to p=reject")
        elif policy == "none":
            result.add_message(
                "warning", 
                "DMARC policy is 'none' (monitoring only, no protection)"
            )
            result.add_remediation(
                "Upgrade DMARC policy to p=quarantine or p=reject after analyzing reports"
            )
        else:
            result.add_message("error", "DMARC policy (p=) not specified or invalid")
            result.add_remediation("Add a policy tag: p=reject")
        
        # Check 3: RUA (aggregate reports)
        rua = parsed.get("rua", "")
        rua_uris = self._parse_uris(rua)
        result.parsed_data["rua_uris"] = rua_uris
        
        if rua_uris:
            result.points += self.POINTS_RUA
            result.add_message(
                "success", 
                f"Aggregate reporting configured: {len(rua_uris)} recipient(s)"
            )
        else:
            result.add_message("warning", "No aggregate reporting (rua) configured")
            result.add_remediation("Add rua=mailto:dmarc-reports@yourdomain.com for visibility")
        
        # Check 4: Alignment (adkim, aspf)
        adkim = parsed.get("adkim", "r").lower()  # Default is relaxed
        aspf = parsed.get("aspf", "r").lower()    # Default is relaxed
        
        result.parsed_data["adkim"] = adkim
        result.parsed_data["aspf"] = aspf
        
        strict_count = (1 if adkim == "s" else 0) + (1 if aspf == "s" else 0)
        
        if strict_count == 2:
            result.points += self.POINTS_STRICT_BOTH
            result.add_message("success", "Both DKIM and SPF alignment are strict")
        elif strict_count == 1:
            result.points += self.POINTS_STRICT_ONE
            strict_which = "DKIM" if adkim == "s" else "SPF"
            relaxed_which = "SPF" if adkim == "s" else "DKIM"
            result.add_message(
                "info", 
                f"{strict_which} alignment is strict, {relaxed_which} is relaxed"
            )
            result.add_remediation(
                f"Consider setting {relaxed_which.lower()} alignment to strict (a{relaxed_which.lower()[0]}=s)"
            )
        else:
            result.add_message(
                "info", 
                "Both DKIM and SPF alignment are relaxed (default)"
            )
            result.add_remediation(
                "Consider strict alignment (adkim=s; aspf=s) for better protection"
            )
        
        # Check 5: Failure reporting options (fo)
        fo = parsed.get("fo", "0")
        result.parsed_data["fo"] = fo
        
        # fo=1 means report on any failure, s=SPF failure, d=DKIM failure
        if any(opt in fo for opt in ["1", "s", "d"]):
            result.points += self.POINTS_FO
            result.add_message("success", f"Failure reporting enabled (fo={fo})")
        else:
            result.add_message(
                "info", 
                "Failure reporting set to default (fo=0, only on full failure)"
            )
            result.add_remediation("Add fo=1 for detailed failure reports")
        
        # Check 6: Percentage (pct)
        pct_str = parsed.get("pct", "100")
        try:
            pct = int(pct_str)
        except ValueError:
            pct = 100
        
        result.parsed_data["pct"] = pct
        
        if pct == 100:
            result.points += self.POINTS_PCT_100
            result.add_message("success", "Policy applies to 100% of messages")
        elif pct > 0:
            result.points += self.POINTS_PCT_PARTIAL
            result.add_message(
                "info", 
                f"Policy applies to {pct}% of messages (rollout mode)"
            )
            result.add_remediation("Increase pct to 100 after testing")
        else:
            result.add_message("warning", "pct=0 means policy is not being applied")
            result.add_remediation("Set pct to 100 to enforce your policy")
        
        # Check 7: Subdomain policy (sp)
        sp = parsed.get("sp", "").lower()
        parent_policy = policy
        
        if sp:
            result.parsed_data["sp"] = sp
            if sp == parent_policy or (not parent_policy and sp == "none"):
                result.points += self.POINTS_SP
                result.add_message("success", f"Subdomain policy (sp={sp}) is set")
            elif sp in ["reject", "quarantine", "none"]:
                result.points += self.POINTS_SP
                result.add_message(
                    "info", 
                    f"Subdomain policy (sp={sp}) differs from parent ({parent_policy})"
                )
            else:
                result.add_message("warning", f"Invalid subdomain policy: sp={sp}")
        else:
            result.add_message(
                "info", 
                "No subdomain policy (sp) set - inherits parent policy"
            )
        
        return result
    
    def _parse_dmarc(self, dmarc: str) -> Dict[str, str]:
        """
        Parse a DMARC record into tag-value pairs.
        
        Args:
            dmarc: The DMARC TXT record
            
        Returns:
            Dictionary of tag -> value pairs
        """
        result = {}
        
        # Split by semicolon
        parts = [p.strip() for p in dmarc.split(";")]
        
        for part in parts:
            if "=" in part:
                tag, value = part.split("=", 1)
                result[tag.strip().lower()] = value.strip()
        
        return result
    
    def _parse_uris(self, uri_string: str) -> List[str]:
        """
        Parse URI list (like rua/ruf values).
        
        Args:
            uri_string: Comma-separated list of URIs
            
        Returns:
            List of valid mailto: URIs
        """
        if not uri_string:
            return []
        
        uris = []
        for uri in uri_string.split(","):
            uri = uri.strip()
            if uri.lower().startswith("mailto:"):
                uris.append(uri)
        
        return uris
