"""
MX Checker Module

Validates MX (Mail Exchange) records for a domain.

Scoring (10 points total):
- +5: At least one MX record present
- +5: All MX hosts resolve (no dangling entries)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from scanner.checkers.base import BaseChecker, CheckResult
from scanner.services.dns_resolver import get_resolver


class MXChecker(BaseChecker):
    """
    MX record checker.
    
    Validates:
    1. MX records exist
    2. All MX hosts resolve to valid IPs
    """
    
    name = "mx"
    max_points = 10
    
    # Points breakdown
    POINTS_MX_EXISTS = 5
    POINTS_ALL_RESOLVE = 5
    
    def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Check MX records for the domain.
        
        Returns:
            CheckResult with MX validation results
        """
        result = self._create_result()
        resolver = get_resolver()
        
        # Get MX records
        mx_records = resolver.resolve_mx(domain)
        
        # Store raw records
        result.raw_records = [f"{priority} {host}" for priority, host in mx_records]
        result.parsed_data["records"] = [
            {"priority": p, "host": h} for p, h in mx_records
        ]
        
        # Check 1: MX records exist
        if mx_records:
            result.points += self.POINTS_MX_EXISTS
            result.add_message("success", f"Found {len(mx_records)} MX record(s)")
        else:
            result.add_message("error", "No MX records found")
            result.add_remediation("Add MX records to enable email delivery")
            return result
        
        # Check 2: All MX hosts resolve (using concurrent lookups)
        unresolved = []
        resolved = []
        
        def check_host(host):
            return (host, resolver.host_exists(host))
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_host, host): host for _, host in mx_records}
            for future in as_completed(futures):
                host, exists = future.result()
                if exists:
                    resolved.append(host)
                else:
                    unresolved.append(host)
        
        result.parsed_data["resolved_hosts"] = resolved
        result.parsed_data["unresolved_hosts"] = unresolved
        
        if not unresolved:
            result.points += self.POINTS_ALL_RESOLVE
            result.add_message("success", "All MX hosts resolve correctly")
        else:
            result.add_message(
                "error", 
                f"Dangling MX record(s): {', '.join(unresolved)}"
            )
            result.add_remediation(
                f"Fix or remove dangling MX records: {', '.join(unresolved)}"
            )
        
        return result
