"""
ZeroSpoof Constants

Scoring weights, letter grades, DKIM selectors, and other configuration.
All values here can be adjusted for future scoring profile versions.
"""

# Scoring Profile Version
SCORE_PROFILE_VERSION = "1.0"

# Scoring Weights (out of 100 total)
WEIGHTS = {
    "mx": 10,
    "spf": 25,
    "dkim": 25,
    "dmarc": 40,
}

# Letter Grades (threshold, grade) - order matters, check from highest first
LETTER_GRADES = [
    (95, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (50, "E"),
    (0, "F"),
]

# Microsoft 365 MX suffix for provider detection
M365_MX_SUFFIX = ".mail.protection.outlook.com"

# Common DKIM selectors to probe (best-effort discovery)
COMMON_DKIM_SELECTORS = [
    "selector1",   # Microsoft 365 primary
    "selector2",   # Microsoft 365 secondary
    "google",      # Google Workspace
    "default",     # Common default
    "dkim",        # Generic
    "mail",        # Generic
    "k1",          # Mailchimp
    "s1",          # Generic
    "s2",          # Generic
    "smtp",        # Generic
    "mandrill",    # Mandrill
    "mxvault",     # MXVault
    "everlytickey1",  # Everlytic
    "everlytickey2",  # Everlytic
]

# M365-specific selectors
M365_DKIM_SELECTORS = ["selector1", "selector2"]

# Valid SPF mechanisms (for syntax validation)
VALID_SPF_MECHANISMS = [
    "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect", "exp"
]

# SPF lookup-counting mechanisms (count towards 10-lookup limit)
SPF_LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists", "redirect"]

# Valid DMARC tags
VALID_DMARC_TAGS = [
    "v", "p", "sp", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri"
]

# DNS configuration
DNS_TIMEOUT = 5  # seconds
DNS_LIFETIME = 10  # seconds
