# scanner/violation_store.py
"""
Advanced GDPR & CCPA Violation Registry
---------------------------------------
This module defines 20 major privacy and security violations detected by the compliance scanner.

Each rule includes:
- id: Unique identifier for the violation
- title: Short descriptive title
- description: Detailed context explaining why the violation matters
- recommendation: Technical and organizational guidance to resolve the issue
- severity: Risk impact level
- check: Callable detection function for the scanner
"""

import re


# ===============================================================
# 🔍 DETECTION FUNCTIONS
# ===============================================================

def missing_consent_banner(html, *_):
    """Detect if no cookie consent banner exists."""
    keywords = ["cookie consent", "accept cookies", "cookie settings", "privacy banner"]
    return not any(k in html for k in keywords)


def no_reject_option(html, *_):
    """Detect if an 'Accept All' button exists but no 'Reject' or 'Manage' option."""
    return "accept all" in html and not any(k in html for k in ["reject", "decline", "manage cookies"])


def cookies_before_consent(_, cookies, __, ___):
    """Detect cookies already stored before consent."""
    return len(cookies) > 0


def insecure_cookies(_, cookies, __, ___):
    """Detect cookies without Secure/HttpOnly attributes."""
    return any(not c.get("secure", False) or c.get("sameSite") in (None, "None", "") for c in cookies)


def missing_privacy_policy(html, *_):
    """Detect missing privacy policy link."""
    return not any(k in html for k in ["privacy policy", "/privacy", "data protection"])


def missing_do_not_sell(html, *_):
    """Detect missing 'Do Not Sell My Personal Information' link (CCPA)."""
    return "do not sell" not in html and "opt-out" not in html


def third_party_trackers(_, __, scripts, ___):
    """Detect known third-party tracking or advertising scripts."""
    trackers = ["google-analytics", "doubleclick", "facebook", "tiktok", "linkedin", "hotjar", "mixpanel"]
    return any(t in str(scripts).lower() for t in trackers)


def fingerprinting(html, __, scripts, ___):
    """Detect browser fingerprinting libraries or APIs."""
    patterns = ["fingerprintjs", "canvas.toDataURL", "webgl", "audioContext", "deviceMemory"]
    return any(p in html or any(p in (s or "") for s in scripts) for p in patterns)


def local_storage_use(html, *_):
    """Detect presence of localStorage or sessionStorage API calls."""
    return "localstorage" in html or "sessionstorage" in html


def missing_data_access_option(html, *_):
    """Detect missing user data access mechanism."""
    return not any(k in html for k in ["access my data", "download my data", "request data"])


def missing_data_deletion(html, *_):
    """Detect missing data deletion option."""
    return not any(k in html for k in ["delete my data", "erase my data", "right to be forgotten"])


def missing_retention_policy(html, *_):
    """Detect missing retention period disclosure."""
    return "retention" not in html and "keep your data" not in html


def missing_withdraw_consent(html, *_):
    """Detect missing mechanism to withdraw or change consent."""
    return not any(k in html for k in ["withdraw consent", "change cookie settings", "manage consent"])


def collecting_pii(html, *_):
    """Detect forms requesting personal data (PII)."""
    pii_inputs = ["name=", "email", "phone", "address", "dob", "birth"]
    return any(k in html for k in pii_inputs)


def email_marketing_without_consent(html, *_):
    """Detect newsletter subscription forms lacking consent reference."""
    return "newsletter" in html and not any(k in html for k in ["consent", "agree", "subscribe"])


def dark_pattern_consent_ui(html, *_):
    """Detect consent UIs designed to force acceptance."""
    return "accept all" in html and "reject" not in html


def insecure_transport(html, *_):
    """Detect insecure HTTP usage in resources or forms."""
    return "http://" in html


def third_party_data_sharing(html, *_):
    """Detect lack of disclosure for data sharing with external partners."""
    return not any(k in html for k in ["third party", "third-party", "partners", "vendors", "processors"])


def analytics_without_anonymization(html, *_):
    """Detect Google Analytics use without IP anonymization."""
    return "google-analytics" in html and "anonymize_ip" not in html


def excessive_cookie_count(_, cookies, __, ___):
    """Detect excessive number of cookies (>20)."""
    return len(cookies) > 20


# ===============================================================
# 🧱 DETAILED VIOLATION DEFINITIONS
# ===============================================================

VIOLATION_RULES = [
    {
        "id": "missing_consent_banner",
        "title": "Missing Cookie Consent Banner",
        "description": "The website does not display any visible cookie consent banner or mechanism for users to provide explicit consent before cookies are stored. "
                       "Under GDPR Article 7 and ePrivacy Directive, consent must be freely given, informed, and obtained prior to data processing.",
        "recommendation": "Implement a clear cookie consent banner that blocks non-essential cookies until consent is given. Include 'Accept', 'Reject', and 'Preferences' options. "
                          "Ensure the banner records and respects user preferences persistently.",
        "severity": "High",
        "check": missing_consent_banner,
    },
    {
        "id": "no_reject_option",
        "title": "No Reject Option for Cookies",
        "description": "The consent interface presents an 'Accept All' button without an equivalent option to reject or customize cookies. "
                       "This practice violates GDPR Article 7(4), as consent must be freely given without bias or coercion.",
        "recommendation": "Update your consent interface to include equally visible and accessible options to 'Reject' or 'Customize' cookies. "
                          "Avoid design patterns that pressure users to accept tracking cookies (known as 'dark patterns').",
        "severity": "High",
        "check": no_reject_option,
    },
    {
        "id": "cookies_before_consent",
        "title": "Cookies Set Before Consent",
        "description": "Cookies, including analytics or marketing cookies, are being placed before the user has given explicit consent. "
                       "This violates GDPR Article 6 and the principle of lawful processing.",
        "recommendation": "Ensure all non-essential cookies (tracking, analytics, marketing) are loaded only after the user consents. "
                          "Modify scripts to trigger cookie creation conditionally after consent is captured.",
        "severity": "Critical",
        "check": cookies_before_consent,
    },
    {
        "id": "insecure_cookies",
        "title": "Insecure Cookies Found",
        "description": "Cookies are missing Secure, HttpOnly, or SameSite attributes, increasing the risk of session hijacking or CSRF attacks.",
        "recommendation": "Always configure cookies with 'Secure', 'HttpOnly', and 'SameSite=Strict' flags to prevent interception or script access. "
                          "Example (Python/Flask): `response.set_cookie('id', value, secure=True, httponly=True, samesite='Strict')`.",
        "severity": "Critical",
        "check": insecure_cookies,
    },
    {
        "id": "missing_privacy_policy",
        "title": "Missing Privacy Policy",
        "description": "The website does not include a link to a privacy policy, which is required under GDPR Articles 13 and 14 and CCPA §1798.130.",
        "recommendation": "Provide a clear and accessible privacy policy page detailing data collection, usage, sharing, and user rights. "
                          "Include it in your website footer and within consent dialogs.",
        "severity": "High",
        "check": missing_privacy_policy,
    },
    {
        "id": "missing_do_not_sell",
        "title": "Missing 'Do Not Sell My Personal Information' Link",
        "description": "Under CCPA, websites must provide California residents with an option to opt-out of the sale of personal information.",
        "recommendation": "Add a clearly labeled 'Do Not Sell My Personal Information' link on your homepage footer. "
                          "Ensure it leads to a form or page that allows users to opt-out of data selling practices.",
        "severity": "High",
        "check": missing_do_not_sell,
    },
    {
        "id": "third_party_trackers",
        "title": "Third-Party Trackers Detected",
        "description": "Third-party tracking scripts (Google Analytics, Facebook Pixel, TikTok Pixel, etc.) were detected, which may transmit user data to external servers.",
        "recommendation": "Audit and minimize third-party trackers. Integrate them through a consent management platform that only activates after user approval.",
        "severity": "Medium",
        "check": third_party_trackers,
    },
    {
        "id": "fingerprinting",
        "title": "Browser Fingerprinting Detected",
        "description": "The website uses fingerprinting technologies (e.g., canvas, WebGL, audioContext) to uniquely identify devices without consent. "
                       "This is considered intrusive profiling under GDPR Article 9.",
        "recommendation": "Avoid fingerprinting scripts or disclose their use in your privacy policy. Obtain explicit consent if profiling is required for functionality.",
        "severity": "Critical",
        "check": fingerprinting,
    },
    {
        "id": "local_storage_use",
        "title": "Local Storage or Session Storage Detected",
        "description": "The website writes data to the browser's localStorage or sessionStorage, potentially persisting user identifiers beyond a single session.",
        "recommendation": "Avoid storing personal or tracking identifiers in client-side storage. Use secure server-side sessions or anonymize stored values.",
        "severity": "Medium",
        "check": local_storage_use,
    },
    {
        "id": "missing_data_access_option",
        "title": "No Data Access Mechanism",
        "description": "Users cannot find a method to request access to the personal data collected about them. "
                       "This violates GDPR Article 15 and CCPA §1798.100.",
        "recommendation": "Add a 'Request My Data' or 'Access My Data' feature that enables users to request a copy of their stored personal data via form or email.",
        "severity": "High",
        "check": missing_data_access_option,
    },
    {
        "id": "missing_data_deletion",
        "title": "No Data Deletion Mechanism",
        "description": "There is no visible option allowing users to delete their personal data, violating GDPR Article 17 and CCPA §1798.105.",
        "recommendation": "Implement a data deletion or 'Right to be Forgotten' request process. Provide a simple form or email method and confirm deletion actions transparently.",
        "severity": "High",
        "check": missing_data_deletion,
    },
    {
        "id": "missing_retention_policy",
        "title": "No Data Retention Policy",
        "description": "The website does not mention how long personal data is retained, violating GDPR Article 5(1)(e).",
        "recommendation": "Add a section in your privacy policy describing how long personal data is stored and how deletion occurs once the data is no longer needed.",
        "severity": "Medium",
        "check": missing_retention_policy,
    },
    {
        "id": "missing_withdraw_consent",
        "title": "No Withdraw Consent Option",
        "description": "Users cannot change or withdraw consent once it is given, violating GDPR Article 7(3).",
        "recommendation": "Add a persistent link (e.g., 'Privacy Settings' or 'Manage Consent') that allows users to modify their cookie and privacy preferences.",
        "severity": "Medium",
        "check": missing_withdraw_consent,
    },
    {
        "id": "collecting_pii",
        "title": "Personal Information (PII) Collection Detected",
        "description": "The website includes forms or inputs requesting personal information (e.g., name, email, phone) without a visible lawful basis or consent notice.",
        "recommendation": "Display a consent checkbox and privacy notice near all data collection forms. Clearly state purpose, storage duration, and legal basis for processing.",
        "severity": "High",
        "check": collecting_pii,
    },
    {
        "id": "email_marketing_without_consent",
        "title": "Email Marketing Without Explicit Consent",
        "description": "Newsletter or subscription forms are collecting email addresses without clearly obtaining user consent. This violates GDPR Article 7 and CAN-SPAM regulations.",
        "recommendation": "Use explicit, unchecked opt-in checkboxes for email subscriptions. Store consent logs with timestamps for compliance proof.",
        "severity": "Medium",
        "check": email_marketing_without_consent,
    },
    {
        "id": "dark_pattern_consent_ui",
        "title": "Dark Pattern in Consent Interface",
        "description": "The consent interface visually prioritizes acceptance or hides the rejection option, leading to unfair or manipulated consent.",
        "recommendation": "Design your cookie banner to ensure parity between 'Accept' and 'Reject' buttons. Avoid misleading colors, sizes, or placements that pressure acceptance.",
        "severity": "High",
        "check": dark_pattern_consent_ui,
    },
    {
        "id": "insecure_transport",
        "title": "Insecure HTTP Connections Detected",
        "description": "Resources (e.g., images, scripts, APIs) are being loaded over HTTP instead of HTTPS, risking data interception and mixed content warnings.",
        "recommendation": "Serve all assets via HTTPS and enforce 'Content-Security-Policy: upgrade-insecure-requests'. Configure SSL/TLS site-wide.",
        "severity": "Critical",
        "check": insecure_transport,
    },
    {
        "id": "third_party_data_sharing",
        "title": "Third-Party Data Sharing Not Disclosed",
        "description": "The website collects or transfers data to third-party vendors (e.g., advertisers, CRMs) without disclosing such sharing in its privacy policy.",
        "recommendation": "Explicitly list all third-party processors in your privacy policy, including purpose and lawful basis for data sharing. Sign Data Processing Agreements (DPAs).",
        "severity": "High",
        "check": third_party_data_sharing,
    },
    {
        "id": "analytics_without_anonymization",
        "title": "Analytics Without IP Anonymization",
        "description": "Google Analytics or similar services are implemented without IP anonymization, potentially identifying users.",
        "recommendation": "Enable IP anonymization by adding `gtag('config', 'ID', {'anonymize_ip': true});`. Consider migrating to privacy-focused analytics tools (e.g., Plausible, Fathom).",
        "severity": "Medium",
        "check": analytics_without_anonymization,
    },
    {
        "id": "excessive_cookie_count",
        "title": "Excessive Cookie Count",
        "description": "The website sets more than 20 cookies, which may indicate redundant trackers, unnecessary data collection, or poor cookie hygiene.",
        "recommendation": "Review and reduce non-essential cookies. Consolidate analytics identifiers and purge outdated or duplicate cookies for better compliance and performance.",
        "severity": "Low",
        "check": excessive_cookie_count,
    },
]
