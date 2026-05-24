"""
Application-wide constants.

These are hardcoded values that do not change between environments.
For values that vary by environment, use settings.py instead.
"""

from __future__ import annotations

# ==============================================================================
# DNS RECORD TYPES
# ==============================================================================

class DNSRecordType:
    A       = "A"
    AAAA    = "AAAA"
    MX      = "MX"
    TXT     = "TXT"
    NS      = "NS"
    CNAME   = "CNAME"
    SOA     = "SOA"
    DS      = "DS"
    DNSKEY  = "DNSKEY"
    RRSIG   = "RRSIG"
    CAA     = "CAA"
    PTR     = "PTR"
    SRV     = "SRV"


# ==============================================================================
# SEVERITY LEVELS
# ==============================================================================

class Severity:
    CRITICAL  = "critical"    # Immediate action required (e.g. zone transfer exposed)
    HIGH      = "high"        # Significant risk (e.g. no DMARC)
    MEDIUM    = "medium"      # Moderate risk (e.g. DMARC policy = none)
    LOW       = "low"         # Minor issue (e.g. missing CAA record)
    INFO      = "info"        # Informational, no action required

    ALL: list[str] = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

    # Numeric weights for scoring (used in scorer.py)
    WEIGHTS: dict[str, int] = {
        CRITICAL: 100,
        HIGH:     75,
        MEDIUM:   40,
        LOW:      15,
        INFO:     0,
    }


# ==============================================================================
# SCORE GRADES
# ==============================================================================

class Grade:
    """Letter grade thresholds (0–100, higher = better security posture)."""

    A_PLUS  = (95, 100, "A+")
    A       = (85, 94,  "A")
    B       = (70, 84,  "B")
    C       = (55, 69,  "C")
    D       = (40, 54,  "D")
    F       = (0,  39,  "F")

    THRESHOLDS = [A_PLUS, A, B, C, D, F]

    @classmethod
    def from_score(cls, score: int) -> str:
        for low, high, grade in cls.THRESHOLDS:
            if low <= score <= high:
                return grade
        return "F"


# ==============================================================================
# SPF CONSTANTS
# ==============================================================================

class SPF:
    MAX_DNS_LOOKUPS    = 10       # RFC 7208 hard limit
    WARN_DNS_LOOKUPS   = 8        # Warn before hitting the limit
    PREFIX             = "v=spf1"
    MECHANISMS         = ("include", "a", "mx", "ptr", "exists", "redirect")
    QUALIFIERS         = ("+", "-", "~", "?")


# ==============================================================================
# DMARC CONSTANTS
# ==============================================================================

class DMARC:
    PREFIX            = "v=DMARC1"
    RECORD_NAME       = "_dmarc"
    POLICY_NONE       = "none"
    POLICY_QUARANTINE = "quarantine"
    POLICY_REJECT     = "reject"

    # Ordered from weakest to strongest
    POLICY_ORDER: list[str] = [POLICY_NONE, POLICY_QUARANTINE, POLICY_REJECT]


# ==============================================================================
# DKIM CONSTANTS
# ==============================================================================

class DKIM:
    RECORD_SUFFIX        = "._domainkey"
    MIN_KEY_BITS         = 1024    # Minimum acceptable RSA key size
    RECOMMENDED_KEY_BITS = 2048   # Recommended RSA key size

    # Common selectors to brute-force (augmented by wordlist)
    COMMON_SELECTORS: list[str] = [
        "default", "dkim", "mail", "email", "google", "k1", "k2", "s1", "s2",
        "selector1", "selector2", "smtp", "postfix", "sendgrid", "mandrill",
        "mailchimp", "ses", "protonmail", "zoho", "office365", "exchange",
    ]


# ==============================================================================
# DNSSEC CONSTANTS
# ==============================================================================

class DNSSEC:
    ALGORITHM_NAMES: dict[int, str] = {
        5:  "RSASHA1",
        7:  "RSASHA1-NSEC3-SHA1",
        8:  "RSASHA256",
        10: "RSASHA512",
        13: "ECDSAP256SHA256",
        14: "ECDSAP384SHA384",
        15: "ED25519",
        16: "ED448",
    }
    WEAK_ALGORITHMS: set[int] = {1, 3, 5, 6, 7}   # MD5, SHA1-based = weak


# ==============================================================================
# SUBDOMAIN TAKEOVER FINGERPRINTS
# ==============================================================================

# Maps CNAME patterns to the service they indicate.
# If a subdomain CNAMEs to these patterns and the service is unclaimed,
# it may be vulnerable to takeover.
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "github.io":                "GitHub Pages",
    "s3.amazonaws.com":         "Amazon S3",
    "s3-website":               "Amazon S3 Website",
    "cloudfront.net":           "Amazon CloudFront",
    "herokuapp.com":            "Heroku",
    "herokudns.com":            "Heroku DNS",
    "azurewebsites.net":        "Microsoft Azure",
    "trafficmanager.net":       "Azure Traffic Manager",
    "blob.core.windows.net":    "Azure Blob Storage",
    "cloudapp.net":             "Azure Cloud",
    "netlify.app":              "Netlify",
    "netlify.com":              "Netlify",
    "pages.dev":                "Cloudflare Pages",
    "ghost.io":                 "Ghost",
    "myshopify.com":            "Shopify",
    "zendesk.com":              "Zendesk",
    "desk.com":                 "Desk.com",
    "helpscoutdocs.com":        "HelpScout",
    "readme.io":                "Readme.io",
    "surge.sh":                 "Surge.sh",
    "fastly.net":               "Fastly",
    "unbouncepages.com":        "Unbounce",
    "webflow.io":               "Webflow",
    "strikingly.com":           "Strikingly",
    "bitbucket.io":             "Bitbucket",
    "cargo.site":               "Cargo",
}


# ==============================================================================
# HTTP TIMEOUTS
# ==============================================================================

class Timeout:
    DEFAULT_SECONDS     = 10.0
    INTEL_API_SECONDS   = 15.0
    DNS_QUERY_SECONDS   = 5.0
    REPORT_SECONDS      = 60.0


# ==============================================================================
# API RESPONSES
# ==============================================================================

class ScanStatus:
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


# ==============================================================================
# CACHE KEYS
# ==============================================================================

class CacheKey:
    """Cache key templates. Use .format() to fill in variables."""

    SCAN_RESULT     = "scan:result:{scan_id}"
    DOMAIN_FINDINGS = "domain:findings:{domain}"
    INTEL_IP        = "intel:ip:{ip}"
    INTEL_DOMAIN    = "intel:domain:{domain}"
    SPF_RECORD      = "dns:spf:{domain}"
    DMARC_RECORD    = "dns:dmarc:{domain}"
    NS_RECORDS      = "dns:ns:{domain}"


# ==============================================================================
# MISC
# ==============================================================================

# Maximum number of domains per bulk scan request
MAX_BULK_DOMAINS = 500

# Maximum subdomains returned per scan
MAX_SUBDOMAINS_RETURNED = 1000

# MTA-STS well-known URL template
MTA_STS_POLICY_URL = "https://mta-sts.{domain}/.well-known/mta-sts.txt"

# TLSRPT record prefix
TLSRPT_RECORD_PREFIX = "v=TLSRPTv1"

# CAA issue tag values
CAA_TAGS = ("issue", "issuewild", "iodef")