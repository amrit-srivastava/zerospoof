"""
SPF Checker Module

Validates SPF (Sender Policy Framework) records for a domain.

Scoring (25 points total):
- +5: SPF record present (v=spf1)
- +5: Syntax valid; no unknown/duplicate mechanisms
- +2: DNS lookups ≤ 10
- +3: All hosts resolve (no dangling entries) and are online
- +6: Terminal is -all (if ~all: +3; missing: 0; +all: entire SPF score = 0)
- +4: No ptr; no excessive expansion
"""

import re
from typing import List, Optional, Set, Tuple

from scanner.checkers.base import BaseChecker, CheckResult
from scanner.services.dns_resolver import get_resolver
from scanner.constants import VALID_SPF_MECHANISMS, SPF_LOOKUP_MECHANISMS


class SPFChecker(BaseChecker):
    """
    SPF record checker.
    
    Validates:
    1. SPF record exists
    2. Syntax is valid
    3. DNS lookup count
    4. Host resolution
    5. Terminal qualifier
    6. Absence of ptr and excessive expansion
    """
    
    name = "spf"
    max_points = 25
    
    # Points breakdown
    POINTS_EXISTS = 5
    POINTS_SYNTAX_VALID = 5
    POINTS_LOOKUP_LIMIT = 2
    POINTS_HOSTS_RESOLVE = 3
    POINTS_TERMINAL_ALL = 6      # -all
    POINTS_TERMINAL_SOFTFAIL = 3  # ~all
    POINTS_NO_PTR = 4
    
    def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Check SPF record for the domain.
        
        Returns:
            CheckResult with SPF validation results
        """
        result = self._create_result()
        resolver = get_resolver()
        
        # Get SPF record
        spf_record = resolver.get_spf_record(domain)
        
        if spf_record:
            result.raw_records = [spf_record]
        
        # Check 1: SPF record exists
        if not spf_record:
            result.add_message("error", "No SPF record found")
            result.add_remediation(
                "Add an SPF record: v=spf1 include:<your-mail-provider> -all"
            )
            return result
        
        result.points += self.POINTS_EXISTS
        result.add_message("success", "SPF record found")
        
        # Parse the SPF record
        parsed = self._parse_spf(spf_record)
        result.parsed_data = parsed
        
        # Check for +all (immediate fail)
        if parsed.get("terminal") == "+all":
            result.points = 0  # Reset to 0 as per spec
            result.add_message("error", "SPF uses +all which allows anyone to spoof your domain")
            result.add_remediation("Change +all to -all to reject unauthorized senders")
            return result
        
        # Check 2: Syntax valid
        syntax_errors = parsed.get("syntax_errors", [])
        duplicate_mechanisms = parsed.get("duplicates", [])
        
        if not syntax_errors and not duplicate_mechanisms:
            result.points += self.POINTS_SYNTAX_VALID
            result.add_message("success", "SPF syntax is valid")
        else:
            if syntax_errors:
                for error in syntax_errors:
                    result.add_message("error", f"Syntax error: {error}")
                result.add_remediation("Fix SPF syntax errors")
            if duplicate_mechanisms:
                result.add_message(
                    "warning", 
                    f"Duplicate mechanisms: {', '.join(duplicate_mechanisms)}"
                )
                result.add_remediation("Remove duplicate mechanisms from SPF record")
        
        # Check 3: DNS lookup count
        lookup_count = parsed.get("lookup_count", 0)
        result.parsed_data["lookup_count"] = lookup_count
        
        if lookup_count <= 10:
            result.points += self.POINTS_LOOKUP_LIMIT
            result.add_message("success", f"DNS lookups: {lookup_count}/10")
        else:
            result.add_message(
                "error", 
                f"Too many DNS lookups: {lookup_count}/10 (SPF may fail)"
            )
            result.add_remediation(
                "Reduce DNS lookups by flattening includes or using ip4/ip6 instead"
            )
        
        # Check 4: All hosts resolve (only for 'a' and 'mx' mechanisms, not 'include')
        # 'include' domains contain TXT/SPF records, not A records
        hosts_to_check = parsed.get("hosts_to_check", [])
        unresolved = []
        
        for host in hosts_to_check:
            if not resolver.host_exists(host):
                unresolved.append(host)
        
        result.parsed_data["unresolved_hosts"] = unresolved
        
        if not hosts_to_check or not unresolved:
            result.points += self.POINTS_HOSTS_RESOLVE
            result.add_message("success", "All referenced hosts resolve")
        else:
            result.add_message(
                "warning", 
                f"Unresolved hosts: {', '.join(unresolved)}"
            )
            result.add_remediation(
                f"Fix or remove references to unresolved hosts: {', '.join(unresolved)}"
            )
        
        # Check 5: Terminal qualifier
        terminal = parsed.get("terminal")
        if terminal == "-all":
            result.points += self.POINTS_TERMINAL_ALL
            result.add_message("success", "SPF uses -all (strict reject)")
        elif terminal == "~all":
            result.points += self.POINTS_TERMINAL_SOFTFAIL
            result.add_message(
                "warning", 
                "SPF uses ~all (soft fail) - consider upgrading to -all"
            )
            result.add_remediation("Change ~all to -all for stricter enforcement")
        elif terminal == "?all":
            result.add_message("warning", "SPF uses ?all (neutral) - this provides no protection")
            result.add_remediation("Change ?all to -all for protection")
        else:
            result.add_message("warning", "SPF missing terminal 'all' mechanism")
            result.add_remediation("Add -all at the end of your SPF record")
        
        # Check 6: No ptr and no excessive expansion
        has_ptr = parsed.get("has_ptr", False)
        excessive_includes = parsed.get("include_count", 0) > 5
        
        if not has_ptr and not excessive_includes:
            result.points += self.POINTS_NO_PTR
            result.add_message("success", "No deprecated ptr mechanism used")
        else:
            if has_ptr:
                result.add_message(
                    "warning", 
                    "SPF uses ptr mechanism (deprecated and unreliable)"
                )
                result.add_remediation("Remove ptr mechanism from SPF record")
            if excessive_includes:
                result.add_message(
                    "info", 
                    f"Many includes ({parsed.get('include_count', 0)}) - consider flattening"
                )
        
        return result
    
    def _parse_spf(self, spf: str) -> dict:
        """
        Parse an SPF record and extract components.
        
        Returns:
            Dictionary with parsed data:
            - mechanisms: list of mechanisms found
            - terminal: the 'all' qualifier (-all, ~all, +all, ?all)
            - lookup_count: number of DNS lookups
            - syntax_errors: list of syntax issues
            - duplicates: list of duplicate mechanisms
            - has_ptr: whether ptr is used
            - hosts_to_check: hostnames that need resolution
            - include_count: number of includes
        """
        result = {
            "mechanisms": [],
            "terminal": None,
            "lookup_count": 0,
            "syntax_errors": [],
            "duplicates": [],
            "has_ptr": False,
            "hosts_to_check": [],
            "include_count": 0,
        }
        
        # Split by whitespace
        parts = spf.split()
        
        if not parts or not parts[0].lower().startswith("v=spf1"):
            result["syntax_errors"].append("Missing or invalid v=spf1")
            return result
        
        seen_mechanisms = set()
        
        for part in parts[1:]:  # Skip v=spf1
            part_lower = part.lower()
            
            # Check for 'all' terminal
            if part_lower in ["-all", "~all", "+all", "?all"]:
                result["terminal"] = part_lower
                continue
            elif part_lower == "all":
                result["terminal"] = "+all"  # Implicit +
                continue
            
            # Parse mechanism
            qualifier = "+"  # Default qualifier
            if part[0] in "+-~?":
                qualifier = part[0]
                part = part[1:]
                part_lower = part.lower()
            
            # Extract mechanism name and value
            if ":" in part:
                mech_name, mech_value = part.split(":", 1)
            elif "=" in part:
                mech_name, mech_value = part.split("=", 1)
            elif "/" in part:
                mech_name = part.split("/")[0]
                mech_value = part
            else:
                mech_name = part
                mech_value = None
            
            mech_name_lower = mech_name.lower()
            
            # Check for valid mechanism
            if mech_name_lower not in VALID_SPF_MECHANISMS:
                result["syntax_errors"].append(f"Unknown mechanism: {mech_name}")
                continue
            
            # Track mechanism
            result["mechanisms"].append({
                "qualifier": qualifier,
                "mechanism": mech_name_lower,
                "value": mech_value,
            })
            
            # Check for duplicates
            mech_key = f"{mech_name_lower}:{mech_value}" if mech_value else mech_name_lower
            if mech_key in seen_mechanisms:
                result["duplicates"].append(mech_key)
            seen_mechanisms.add(mech_key)
            
            # Count DNS lookups
            if mech_name_lower in SPF_LOOKUP_MECHANISMS:
                result["lookup_count"] += 1
                
                # Track hosts for resolution check (only 'a' and 'mx', not 'include')
                # 'include' domains contain SPF TXT records, not A/AAAA records
                if mech_value and mech_name_lower in ["a", "mx"]:
                    result["hosts_to_check"].append(mech_value)
            
            # Check for ptr
            if mech_name_lower == "ptr":
                result["has_ptr"] = True
            
            # Count includes
            if mech_name_lower == "include":
                result["include_count"] += 1
        
        return result
