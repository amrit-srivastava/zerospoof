"""
Base Checker Class

Abstract base class for all security checkers (MX, SPF, DKIM, DMARC).
Defines the common interface and result structure.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CheckResult:
    """
    Result from a security check.
    
    Attributes:
        control: The control name (mx, spf, dkim, dmarc)
        points: Points earned
        max_points: Maximum possible points
        messages: List of informational/warning messages
        raw_records: Raw DNS records found
        parsed_data: Parsed/structured data
        remediation: Suggested fixes for issues found
    """
    control: str
    points: int
    max_points: int
    messages: List[Dict[str, str]] = field(default_factory=list)
    raw_records: List[str] = field(default_factory=list)
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    remediation: List[str] = field(default_factory=list)
    
    def add_message(self, level: str, text: str):
        """Add a message with level: info, warning, error, success."""
        self.messages.append({"level": level, "text": text})
    
    def add_remediation(self, text: str):
        """Add a remediation suggestion."""
        self.remediation.append(text)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "control": self.control,
            "points": self.points,
            "max_points": self.max_points,
            "messages": self.messages,
            "raw_records": self.raw_records,
            "parsed_data": self.parsed_data,
            "remediation": self.remediation,
        }


class BaseChecker(ABC):
    """
    Abstract base class for security checkers.
    
    Each checker must implement:
    - name: The control name
    - max_points: Maximum points available
    - check(): The main check method
    """
    
    name: str = ""
    max_points: int = 0
    
    @abstractmethod
    def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Perform the security check.
        
        Args:
            domain: The domain to check
            **kwargs: Additional context (e.g., MX records for provider detection)
            
        Returns:
            CheckResult with points, messages, and data
        """
        pass
    
    def _create_result(self) -> CheckResult:
        """Create an empty result for this checker."""
        return CheckResult(
            control=self.name,
            points=0,
            max_points=self.max_points,
        )
