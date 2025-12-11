"""
Scoring Engine Service

Aggregates results from all checkers and calculates the overall score and letter grade.
Supports versioning for future scoring profile changes.
"""

from typing import Any, Dict, List

from scanner.constants import WEIGHTS, LETTER_GRADES, SCORE_PROFILE_VERSION
from scanner.checkers.base import CheckResult


def calculate_grade(score: int) -> str:
    """
    Calculate the letter grade from a numeric score.
    
    Args:
        score: The total score (0-100)
        
    Returns:
        Letter grade (A+, A, B, C, D, E, F)
    """
    for threshold, grade in LETTER_GRADES:
        if score >= threshold:
            return grade
    return "F"


def get_grade_color(grade: str) -> str:
    """
    Get the color associated with a grade for UI display.
    
    Args:
        grade: The letter grade
        
    Returns:
        CSS color value
    """
    colors = {
        "A+": "#00c853",  # Green
        "A": "#00e676",   # Light green
        "B": "#2979ff",   # Blue
        "C": "#ffea00",   # Yellow
        "D": "#ff9100",   # Orange
        "E": "#ff6d00",   # Dark orange
        "F": "#ff1744",   # Red
    }
    return colors.get(grade, "#666")


class ScanResult:
    """
    Complete scan result containing all check results and overall score.
    """
    
    def __init__(self, domain: str):
        self.domain = domain
        self.score = 0
        self.max_score = 100
        self.grade = "F"
        self.grade_color = "#ff1744"
        self.score_version = SCORE_PROFILE_VERSION
        self.provider = "unknown"
        self.checks: Dict[str, CheckResult] = {}
        self.all_remediation: List[str] = []
    
    def add_check_result(self, result: CheckResult):
        """Add a check result to the scan."""
        self.checks[result.control] = result
        self.all_remediation.extend(result.remediation)
    
    def calculate_final_score(self):
        """Calculate the final score and grade from all checks."""
        self.score = sum(
            check.points for check in self.checks.values()
        )
        self.grade = calculate_grade(self.score)
        self.grade_color = get_grade_color(self.grade)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "domain": self.domain,
            "score": self.score,
            "max_score": self.max_score,
            "grade": self.grade,
            "grade_color": self.grade_color,
            "score_version": self.score_version,
            "provider": self.provider,
            "checks": {
                name: check.to_dict() 
                for name, check in self.checks.items()
            },
            "remediation": self.all_remediation,
        }


class ScoringEngine:
    """
    Main scoring engine that orchestrates all checkers.
    """
    
    def __init__(self):
        # Import checkers here to avoid circular imports
        from scanner.checkers.mx_checker import MXChecker
        from scanner.checkers.spf_checker import SPFChecker
        from scanner.checkers.dkim_checker import DKIMChecker
        from scanner.checkers.dmarc_checker import DMARCChecker
        from scanner.services.provider_detector import get_provider_detector
        from scanner.services.dns_resolver import get_resolver
        
        self.mx_checker = MXChecker()
        self.spf_checker = SPFChecker()
        self.dkim_checker = DKIMChecker()
        self.dmarc_checker = DMARCChecker()
        self.provider_detector = get_provider_detector()
        self.resolver = get_resolver()
    
    def scan(self, domain: str) -> ScanResult:
        """
        Perform a complete security scan of a domain.
        
        Args:
            domain: The domain to scan
            
        Returns:
            ScanResult with all check results and overall score
        """
        result = ScanResult(domain)
        
        # First, get MX records (needed for provider detection)
        mx_records = self.resolver.resolve_mx(domain)
        provider = self.provider_detector.detect(mx_records)
        result.provider = provider.value
        
        # Run all checkers
        mx_result = self.mx_checker.check(domain)
        result.add_check_result(mx_result)
        
        spf_result = self.spf_checker.check(domain)
        result.add_check_result(spf_result)
        
        dkim_result = self.dkim_checker.check(domain, provider=provider)
        result.add_check_result(dkim_result)
        
        dmarc_result = self.dmarc_checker.check(domain)
        result.add_check_result(dmarc_result)
        
        # Calculate final score
        result.calculate_final_score()
        
        return result


# Singleton instance
_engine = None

def get_scoring_engine() -> ScoringEngine:
    """Get the scoring engine instance."""
    global _engine
    if _engine is None:
        _engine = ScoringEngine()
    return _engine
