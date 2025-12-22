"""
Provider Detection Service

Detects email provider based on MX records.
Currently supports Microsoft 365, designed to be pluggable for future providers.
"""

from typing import Optional, List, Tuple
from enum import Enum

from scanner.constants import M365_MX_SUFFIX


class EmailProvider(Enum):
    """Detected email providers."""
    MICROSOFT_365 = "microsoft365"
    GOOGLE_WORKSPACE = "google_workspace"
    UNKNOWN = "unknown"


class ProviderDetector:
    """
    Detects email provider from MX records.
    Designed to be extensible for additional providers.
    """
    
    # Provider detection patterns (suffix -> provider)
    MX_PATTERNS = {
        M365_MX_SUFFIX: EmailProvider.MICROSOFT_365,
        ".google.com": EmailProvider.GOOGLE_WORKSPACE,
        ".googlemail.com": EmailProvider.GOOGLE_WORKSPACE,
        "aspmx.l.google.com": EmailProvider.GOOGLE_WORKSPACE,
    }
    
    def detect(self, mx_records: List[Tuple[int, str]]) -> EmailProvider:
        """
        Detect the email provider from MX records.
        
        Args:
            mx_records: List of (priority, hostname) tuples
            
        Returns:
            Detected EmailProvider enum value
        """
        if not mx_records:
            return EmailProvider.UNKNOWN
        
        for _priority, hostname in mx_records:
            hostname_lower = hostname.lower()
            
            for pattern, provider in self.MX_PATTERNS.items():
                if hostname_lower.endswith(pattern) or hostname_lower == pattern.lstrip('.'):
                    return provider
        
        return EmailProvider.UNKNOWN
    
    def is_microsoft_365(self, mx_records: List[Tuple[int, str]]) -> bool:
        """Check if the domain uses Microsoft 365."""
        return self.detect(mx_records) == EmailProvider.MICROSOFT_365
    
    def is_google_workspace(self, mx_records: List[Tuple[int, str]]) -> bool:
        """Check if the domain uses Google Workspace."""
        return self.detect(mx_records) == EmailProvider.GOOGLE_WORKSPACE


# Singleton instance
_detector = None

def get_provider_detector() -> ProviderDetector:
    """Get the provider detector instance."""
    global _detector
    if _detector is None:
        _detector = ProviderDetector()
    return _detector
