"""
Security rules for VulnScope Lite Security Configuration module.
"""

SCANNER_DEFAULTS = {
    "request_timeout": 10,
    "max_retries": 1,
    "retry_delay": 0.5,
}

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "missing_severity": "Medium",
        "description": (
            "Controls which resources browsers are allowed to load and "
            "reduces exposure to certain injection attacks."
        ),
        "recommendation": (
            "Configure a restrictive Content-Security-Policy appropriate "
            "for the application."
        ),
    },
    "X-Content-Type-Options": {
        "missing_severity": "Low",
        "description": (
            "Helps prevent browsers from MIME-sniffing resources."
        ),
        "recommendation": (
            "Set X-Content-Type-Options to nosniff."
        ),
    },
    "X-Frame-Options": {
        "missing_severity": "Medium",
        "description": (
            "Helps protect pages from clickjacking when framing is not intended."
        ),
        "recommendation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN when appropriate, "
            "and use CSP frame-ancestors for modern deployments."
        ),
    },
    "Referrer-Policy": {
        "missing_severity": "Low",
        "description": (
            "Controls how much referrer information is sent with requests."
        ),
        "recommendation": (
            "Configure an appropriate Referrer-Policy such as "
            "strict-origin-when-cross-origin."
        ),
    },
    "Permissions-Policy": {
        "missing_severity": "Low",
        "classification": "Hardening",
        "risk_contribution": 0,
        "description": (
            "Restricts access to browser features and capabilities."
        ),
        "recommendation": (
            "Configure Permissions-Policy to restrict browser features "
            "not required by the application."
        ),
    },
    "X-XSS-Protection": {
        "missing_severity": "Info",
        "report_when_missing": False,
        "description": (
            "Legacy browser security header. Modern browsers generally "
            "prefer CSP; absence is informational rather than a vulnerability."
        ),
        "recommendation": (
            "Prioritize a strong CSP rather than relying on this legacy header."
        ),
    },
}

# These are configuration/exposure observations based on Recon.
# They are deliberately not presented as confirmed vulnerabilities.
SERVICE_RULES = {
    "telnet": {
        "severity": "High",
        "title": "Telnet Service Exposed",
        "description": (
            "Recon identified a Telnet service. Telnet transmits "
            "authentication and session data without modern encryption."
        ),
        "risk": (
            "Credentials and traffic may be exposed to network interception "
            "when Telnet is used across an untrusted network."
        ),
        "recommendation": (
            "Disable Telnet when not required and use SSH for remote administration."
        ),
    },
    "ftp": {
        "severity": "Medium",
        "title": "FTP Service Exposed",
        "description": (
            "Recon identified an FTP service. Standard FTP does not provide "
            "the same transport protection as encrypted file-transfer protocols."
        ),
        "risk": (
            "Credentials and transferred data may be exposed when FTP is used "
            "without an appropriate encrypted transport."
        ),
        "recommendation": (
            "Disable FTP when unnecessary or migrate to an encrypted alternative "
            "such as SFTP or properly configured FTPS."
        ),
    },
    "smb": {
        "severity": "Medium",
        "title": "SMB Service Exposed",
        "description": (
            "Recon identified an SMB service exposed on the target."
        ),
        "risk": (
            "An unnecessarily exposed file-sharing service increases the "
            "attack surface and may expose shared resources."
        ),
        "recommendation": (
            "Restrict SMB to trusted networks, disable unnecessary shares, "
            "enforce strong authentication, and use secure SMB configurations."
        ),
    },
    "ssh": {
        "severity": "Info",
        "title": "SSH Service Exposed",
        "description": (
            "Recon identified an SSH service. SSH is an encrypted remote "
            "administration protocol, but its configuration should still be hardened."
        ),
        "risk": (
            "Weak authentication or unnecessarily broad network access can "
            "increase the risk associated with remote administration."
        ),
        "recommendation": (
            "Restrict SSH access to trusted networks, prefer key-based "
            "authentication, disable unnecessary authentication methods, "
            "and keep the SSH implementation patched."
        ),
    },
    "mysql": {
        "severity": "Medium",
        "title": "MySQL Service Exposed",
        "description": (
            "Recon identified a MySQL service exposed on the target."
        ),
        "risk": (
            "Direct database exposure increases the attack surface and may "
            "permit unauthorized database access if access controls are weak."
        ),
        "recommendation": (
            "Restrict database access to trusted application hosts and "
            "administrative networks; do not expose the database publicly."
        ),
    },
    "postgresql": {
        "severity": "Medium",
        "title": "PostgreSQL Service Exposed",
        "description": (
            "Recon identified a PostgreSQL service exposed on the target."
        ),
        "risk": (
            "Direct database exposure increases the attack surface and may "
            "permit unauthorized access if network or database controls are weak."
        ),
        "recommendation": (
            "Restrict PostgreSQL access to trusted hosts and networks and "
            "enforce strong authentication."
        ),
    },
    "mssql": {
        "severity": "Medium",
        "title": "MSSQL Service Exposed",
        "description": (
            "Recon identified a Microsoft SQL Server service exposed on the target."
        ),
        "risk": (
            "Direct database exposure increases the attack surface and may "
            "expose sensitive data if access controls are weak."
        ),
        "recommendation": (
            "Restrict MSSQL access to trusted hosts and networks and "
            "enforce strong authentication."
        ),
    },
    "oracle": {
        "severity": "Medium",
        "title": "Oracle Database Service Exposed",
        "description": (
            "Recon identified an Oracle database service exposed on the target."
        ),
        "risk": (
            "Direct database exposure increases the attack surface and may "
            "expose sensitive database resources."
        ),
        "recommendation": (
            "Restrict Oracle listener access to trusted hosts and networks "
            "and enforce strong authentication."
        ),
    },
    "redis": {
        "severity": "Medium",
        "title": "Redis Service Exposed",
        "description": (
            "Recon identified a Redis service exposed on the target."
        ),
        "risk": (
            "An exposed Redis service can create significant risk if it is "
            "reachable by untrusted clients or lacks appropriate authentication."
        ),
        "recommendation": (
            "Bind Redis to trusted interfaces, restrict network access, "
            "and enable appropriate authentication and protected-mode controls."
        ),
    },
    "mongodb": {
        "severity": "Medium",
        "title": "MongoDB Service Exposed",
        "description": (
            "Recon identified a MongoDB service exposed on the target."
        ),
        "risk": (
            "Direct database exposure can allow unauthorized access when "
            "authentication or network restrictions are weak."
        ),
        "recommendation": (
            "Restrict MongoDB to trusted networks, require authentication, "
            "and avoid unnecessary public exposure."
        ),
    },
}

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
    "Info": 0,
}

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}
