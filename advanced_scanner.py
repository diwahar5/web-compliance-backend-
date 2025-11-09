"""
advanced_scanner.py — Powerful GDPR/CCPA Web Compliance Scanner

Usage (CLI):
    python advanced_scanner.py https://example.com

Outputs:
    - A structured Python dict (printed as JSON) with:
        - url, final_url, score
        - violations: list of {id, title, severity, description, recommendation, evidence}
        - metadata: scripts, cookies, requests, localStorage keys, screenshot path (if saved)
Notes:
    - Requires Playwright (pip install playwright) and playwright browsers installed:
        pip install playwright
        python -m playwright install
"""

import sys
import json
import time
import re
import traceback
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# ---------------------------
# Configuration
# ---------------------------
NAV_TIMEOUT = 120_000          # ms
WAIT_AFTER_LOAD = 3.0         # seconds
RETRY_ATTEMPTS = 2
SAVE_SCREENSHOT = True        # whether to save screenshot evidence
SCREENSHOT_PATH_TEMPLATE = "scan_{host}.png"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
)

# ---------------------------
# Helper detection utilities
# ---------------------------
def _safe_goto(page, url: str, timeout: int = NAV_TIMEOUT) -> None:
    last_exc = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            page.wait_for_timeout(int(WAIT_AFTER_LOAD * 1000))
            return
        except PlaywrightTimeoutError as e:
            last_exc = e
            time.sleep(1)
        except Exception as e:
            last_exc = e
            time.sleep(1)
    raise last_exc or RuntimeError("Failed to navigate")

def _find_links(page, patterns: List[str]) -> List[str]:
    found = []
    try:
        anchors = page.query_selector_all("a")
        for a in anchors:
            text = (a.inner_text() or "").lower()
            href = (a.get_attribute("href") or "")
            for p in patterns:
                if p in text or p in href.lower():
                    found.append(href)
    except Exception:
        pass
    return found

def _first_match(strings: List[str], patterns: List[str]) -> bool:
    s = " ".join(strings).lower()
    return any(p in s for p in patterns)

# ---------------------------
# Heuristic detectors (advanced)
# ---------------------------
def detect_consent_banner(html: str, page) -> Tuple[bool, dict]:
    patterns = [
        "cookie consent", "accept cookies", "cookie banner", "cookie settings", "manage cookies",
        "we use cookies", "we use cookies to", "accept all"
    ]
    found = any(p in html for p in patterns)
    details = {"method": "keyword", "matched": [p for p in patterns if p in html]}
    # also inspect dialog role contents
    try:
        dialogs = page.query_selector_all("[role='dialog'], .cookie, .cc-window, .cookie-consent")
        dialog_texts = []
        for d in dialogs:
            txt = (d.inner_text() or "").lower()
            dialog_texts.append(txt)
            if any(p in txt for p in patterns):
                details["method"] = "dialog"
                details["matched"].extend([p for p in patterns if p in txt])
                found = True
    except Exception:
        pass
    return found, details

def detect_reject_option(page) -> Tuple[bool, dict]:
    try:
        selects = page.query_selector_all("button, a, input[type='button'], input[type='submit']")
        candidates = []
        for el in selects:
            txt = (el.inner_text() or "").lower()
            candidates.append(txt)
            if any(k in txt for k in ["reject", "deny", "decline", "manage", "cookie settings", "preferences"]):
                return True, {"matched_text": txt}
        return False, {"sample_texts": candidates[:10]}
    except Exception:
        return False, {}

def detect_fingerprinting(html: str, scripts: List[str], page) -> Tuple[bool, dict]:
    hits = []
    fp_libs = ["fingerprintjs", "fingerprint2", "clientjs", "canvas", "webgl", "audioContext", "deviceMemory", "navigator.hardwareConcurrency"]
    for lib in fp_libs:
        if lib in html:
            hits.append({"source": "html", "matched": lib})
    for s in scripts:
        if s and any(lib in (s or "").lower() for lib in fp_libs):
            hits.append({"source": "script_src", "matched": s})
    # inspect whether canvas toDataURL exists by evaluating function definitions
    try:
        canvas_uses = page.evaluate("""() => {
            try {
                const scripts = Array.from(document.scripts).map(s=>s.textContent||"").join(" ");
                return /toDataURL\\(|getContext\\('webgl'\\)/i.test(scripts) ? true : false;
            } catch(e) { return false; }
        }""")
        if canvas_uses:
            hits.append({"source": "runtime", "matched": "canvas/webgl usage detected"})
    except Exception:
        pass
    return (len(hits) > 0), {"hits": hits}

def detect_local_session_storage(page) -> Tuple[bool, dict]:
    try:
        local_keys = page.evaluate("() => Object.keys(localStorage || {})")
        session_keys = page.evaluate("() => Object.keys(sessionStorage || {})")
        keys = {"localStorage": local_keys, "sessionStorage": session_keys}
        present = bool(local_keys or session_keys)
        return present, keys
    except Exception:
        return False, {}

def detect_cookies_before_consent(initial_cookies: List[dict], post_cookies: List[dict]) -> Tuple[bool, dict]:
    # if initial persistent non-session cookies exist immediately, consider them likely set before consent
    initial_persist = [c for c in initial_cookies if not c.get("session", False)]
    evidence = {"initial_count": len(initial_cookies), "initial_persistent": [c.get("name") for c in initial_persist]}
    return (len(initial_persist) > 0), evidence

def detect_insecure_cookies(cookies: List[dict]) -> Tuple[bool, dict]:
    insecure = []
    for c in cookies:
        # Some drivers may have 'secure' bool; check missing secure or missing samesite
        if not c.get("secure", False) or c.get("sameSite") in (None, "None", ""):
            insecure.append({"name": c.get("name"), "secure": c.get("secure"), "sameSite": c.get("sameSite")})
    return (len(insecure) > 0), {"insecure": insecure}

def detect_http_resources(request_urls: List[str]) -> Tuple[bool, dict]:
    http_resources = [r for r in request_urls if r.startswith("http://")]
    return (len(http_resources) > 0), {"http_resources": http_resources[:20]}

def detect_third_party_trackers(scripts: List[str], request_urls: List[str]) -> Tuple[bool, dict]:
    known = ["google-analytics", "doubleclick", "facebook", "ads", "hotjar", "tiktok", "segment", "mixpanel", "fullstory", "intercom"]
    hits = []
    for s in (scripts or []):
        if not s:
            continue
        low = (s or "").lower()
        for k in known:
            if k in low:
                hits.append({"script": s, "matched": k})
    for r in (request_urls or []):
        low = (r or "").lower()
        for k in known:
            if k in low:
                hits.append({"request": r, "matched": k})
    return (len(hits) > 0), {"hits": hits[:50]}

def detect_personal_data_forms(html: str) -> Tuple[bool, dict]:
    # Look for input fields or patterns indicating PII collection
    patterns = ["name=", "email", "phone", "tel:", "address", "ssn", "social security", "birth", "dob", "date of birth"]
    matches = [p for p in patterns if p in html]
    return (len(matches) > 0), {"matched": matches}

def detect_privacy_policy_and_analyze(page, base_url) -> Tuple[dict, dict]:
    """
    Find privacy policy link, fetch it and do basic NLP checks:
    - presence of 'retention', 'third party', 'delete', 'access', 'do not sell'
    """
    result = {"found": False, "privacy_url": None, "privacy_text_snippet": None}
    analysis = {"retention": False, "third_party": False, "delete": False, "access": False, "do_not_sell": False}
    try:
        links = page.query_selector_all("a")
        hrefs = []
        for a in links:
            href = a.get_attribute("href") or ""
            text = (a.inner_text() or "").lower()
            hrefs.append((href, text))
        # find likely privacy link
        candidates = [h for h,t in hrefs if "privacy" in (h or "").lower() or "privacy" in (t or "")]
        if candidates:
            raw = candidates[0]
            privacy_url = raw if raw.startswith("http") else urljoin(base_url, raw)
            result["found"] = True
            result["privacy_url"] = privacy_url
            # try to navigate and get text
            try:
                page.goto(privacy_url, wait_until="domcontentloaded", timeout=30_000)
                page.wait_for_timeout(1000)
                phtml = (page.content() or "").lower()
                result["privacy_text_snippet"] = phtml[:4000]
                analysis["retention"] = "retention" in phtml or "retain" in phtml or "period" in phtml
                analysis["third_party"] = any(k in phtml for k in ["third party", "third-party", "vendors", "partners", "processors"])
                analysis["delete"] = any(k in phtml for k in ["delete my", "erase my", "right to be forgotten", "remove my"])
                analysis["access"] = any(k in phtml for k in ["access my data", "download my data", "request my data", "portability"])
                analysis["do_not_sell"] = "do not sell" in phtml or "sale of personal information" in phtml
            except Exception:
                pass
    except Exception:
        pass
    return result, analysis

def detect_analytics_anonymize(html: str) -> Tuple[bool, dict]:
    # Check for google analytics with anonymize flag
    if "google-analytics" in html or "gtag(" in html or "analytics.js" in html:
        if "anonymize_ip" in html or "anonymizeip" in html:
            return True, {"anonymize_detected": True}
        return False, {"analytics_present": True, "anonymize_detected": False}
    return False, {"analytics_present": False}

# ---------------------------
# Main scanning engine
# ---------------------------
def powerful_scan(url: str, save_screenshot: bool = SAVE_SCREENSHOT) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "url": url,
        "final_url": None,
        "score": 100,
        "violations": [],
        "metadata": {}
    }

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
    headless=True,
    args=["--no-sandbox", "--disable-setuid-sandbox"]
)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=USER_AGENT,
                viewport={"width": 1280, "height": 800}
            )
            page = context.new_page()

            # Collect network requests/responses
            request_urls: List[str] = []
            response_statuses: List[dict] = []
            console_logs: List[str] = []
            scripts_collected: List[str] = []

            def on_request(req):
                try:
                    request_urls.append(req.url)
                    src = req.url
                    # accumulate script URLs heuristically
                    if req.resource_type == "script":
                        scripts_collected.append(req.url)
                except Exception:
                    pass

            def on_response(resp):
                try:
                    response_statuses.append({"url": resp.url, "status": resp.status})
                except Exception:
                    pass

            def on_console(msg):
                try:
                    console_logs.append(f"{msg.type}: {msg.text}")
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("console", on_console)

            # 1) Initial navigation
            _safe_goto(page, url)
            result["final_url"] = page.url
            base_url = result["final_url"]

            # collect html + initial cookies + scripts
            html = (page.content() or "").lower()
            initial_cookies = context.cookies()
            scripts_srcs = scripts_collected or [s.get_attribute("src") for s in page.query_selector_all("script") if s.get_attribute("src")]
            # also include inline script text to html search by concatenating a small sample
            try:
                inline_scripts = []
                for s in page.query_selector_all("script"):
                    try:
                        txt = s.inner_text()
                        if txt and len(txt) < 50_000:
                            inline_scripts.append(txt[:2000])
                    except Exception:
                        pass
                html_combined = html + " " + " ".join(inline_scripts)
            except Exception:
                html_combined = html

            # snapshot of storage
            local_session_present, storage_details = detect_local_session_storage(page)

            # 2) Attempt consent simulator: find and click 'Reject' and 'Accept' buttons
            consent_buttons = {"accept": None, "reject": None, "manage": None}
            try:
                buttons = page.query_selector_all("button, a, input[type='button'], input[type='submit']")
                for b in buttons:
                    txt = (b.inner_text() or "").lower()
                    if not consent_buttons["accept"] and any(k in txt for k in ["accept all", "accept", "agree"]):
                        consent_buttons["accept"] = b
                    if not consent_buttons["reject"] and any(k in txt for k in ["reject", "decline", "deny"]):
                        consent_buttons["reject"] = b
                    if not consent_buttons["manage"] and any(k in txt for k in ["manage", "preferences", "cookie settings"]):
                        consent_buttons["manage"] = b
            except Exception:
                pass

            # initial cookies snapshot
            initial_cookie_names = [c.get("name") for c in initial_cookies]

            # If we found a reject or manage, try clicking reject first to see if trackers still load
            post_reject_cookies = []
            try:
                if consent_buttons["reject"]:
                    try:
                        consent_buttons["reject"].click()
                        page.wait_for_timeout(1000)
                        post_reject_cookies = context.cookies()
                    except Exception:
                        pass
                elif consent_buttons["manage"]:
                    try:
                        consent_buttons["manage"].click()
                        page.wait_for_timeout(1000)
                        post_reject_cookies = context.cookies()
                    except Exception:
                        pass
            except Exception:
                pass

            # then try clicking accept
            post_accept_cookies = []
            try:
                if consent_buttons["accept"]:
                    try:
                        consent_buttons["accept"].click()
                        page.wait_for_timeout(1500)
                        post_accept_cookies = context.cookies()
                    except Exception:
                        pass
            except Exception:
                pass

            # 3) Follow privacy policy if present and analyze
            privacy_info, privacy_analysis = detect_privacy_policy_and_analyze(page, base_url)

            # 4) gather final metadata
            final_cookies = context.cookies()
            # build evidence lists
            request_urls_snapshot = list(dict.fromkeys(request_urls))  # unique preserve order
            scripts_snapshot = scripts_srcs or scripts_collected

            # 5) Run detectors and assemble violations with evidence
            def add_violation(vid, title, severity, description, recommendation, evidence=None):
                nonlocal result
                result["violations"].append({
                    "id": vid,
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation,
                    "evidence": evidence or {}
                })

            # Detector 1: Missing consent banner
            found_banner, banner_details = detect_consent_banner(html_combined, page)
            if not found_banner:
                add_violation(
                    "missing_consent_banner",
                    "Missing Cookie Consent Banner",
                    "High",
                    ("The site does not appear to show a cookie consent banner or dialog prior to loading cookies. "
                     "GDPR requires valid consent before setting non-essential cookies."),
                    ("Add a consent banner that blocks non-essential scripts/cookies until user consent is obtained. "
                     "Provide Accept, Reject and Preferences options and persist consent status."),
                    {"details": banner_details}
                )

            # Detector 2: No reject option / dark patterns
            has_reject, reject_details = detect_reject_option(page)
            if not has_reject:
                add_violation(
                    "no_reject_option_or_dark_pattern",
                    "No Reject Option or Dark Pattern in Consent UI",
                    "High",
                    ("The cookie consent UI lacks an obvious reject/decline option or uses an 'Accept All' pattern without parity."),
                    ("Ensure 'Reject' or 'Manage Preferences' is as visible as 'Accept'. Avoid manipulative UI."),
                    reject_details
                )

            # Detector 3: Cookies set before consent
            cookies_before, cookies_before_evidence = detect_cookies_before_consent(initial_cookies, post_accept_cookies or final_cookies)
            if cookies_before:
                add_violation(
                    "cookies_before_consent",
                    "Cookies Set Before Consent",
                    "Critical",
                    ("Persistent cookies were present immediately after initial page load; likely non-essential cookies set before consent."),
                    ("Do not set non-essential cookies until after explicit consent. Load analytics only after consent."),
                    cookies_before_evidence
                )

            # Detector 4: Insecure cookies
            insecure_found, insecure_evidence = detect_insecure_cookies(final_cookies)
            if insecure_found:
                add_violation(
                    "insecure_cookies",
                    "Insecure Cookies Detected",
                    "Critical",
                    ("One or more cookies do not include Secure or SameSite attributes or are accessible via JavaScript, increasing attack surface."),
                    ("Mark cookies as Secure and HttpOnly where appropriate and set SameSite attribute. Review server cookie configuration."),
                    insecure_evidence
                )

            # Detector 5: Missing privacy policy
            if not privacy_info.get("found"):
                add_violation(
                    "missing_privacy_policy",
                    "Missing Privacy Policy",
                    "High",
                    ("No privacy policy link was found. Websites must publish an accessible privacy policy describing processing activities."),
                    ("Add a privacy policy link (footer) and ensure it explains data collection, retention, third-party sharing and user rights."),
                    {"privacy_link_found": False}
                )
            else:
                # if privacy found but lacking statements, add findings
                missing_parts = []
                if not privacy_analysis.get("retention"):
                    missing_parts.append("retention_period")
                if not privacy_analysis.get("third_party"):
                    missing_parts.append("third_party_disclosure")
                if not privacy_analysis.get("delete"):
                    missing_parts.append("data_deletion_info")
                if not privacy_analysis.get("access"):
                    missing_parts.append("data_access_info")
                if not privacy_analysis.get("do_not_sell"):
                    # for CCPA: if site likely targets US, but we flag lack of do-not-sell notice
                    missing_parts.append("do_not_sell_optout")
                if missing_parts:
                    add_violation(
                        "privacy_policy_incomplete",
                        "Privacy Policy Missing Key Disclosures",
                        "Medium",
                        ("Privacy policy present but missing some required disclosures such as retention, third-party sharing, access or deletion instructions."),
                        ("Update privacy policy to include retention periods, third party processors, deletion/access instructions and CCPA opt-out information if applicable."),
                        {"missing_sections": missing_parts, "privacy_url": privacy_info.get("privacy_url")}
                    )

            # Detector 6: Third-party trackers
            trackers_found, trackers_evidence = detect_third_party_trackers(scripts_snapshot, request_urls_snapshot)
            if trackers_found:
                add_violation(
                    "third_party_trackers",
                    "Third-Party Trackers Detected",
                    "Medium",
                    ("Third-party analytics/advertising/tracking scripts detected which may transmit user-identifying data to external domains."),
                    ("Integrate third-party trackers conditionally based on user consent. Minimize or replace with privacy-first analytics."),
                    trackers_evidence
                )

            # Detector 7: Fingerprinting
            fp_found, fp_evidence = detect_fingerprinting(html_combined, scripts_snapshot, page)
            if fp_found:
                add_violation(
                    "fingerprinting",
                    "Browser Fingerprinting Detected",
                    "Critical",
                    ("Scripts or DOM patterns indicate device/browser fingerprinting which can uniquely identify users without consent."),
                    ("Avoid fingerprinting or obtain explicit consent. Disclose fingerprinting in privacy policy and provide opt-out."),
                    fp_evidence
                )

            # Detector 8: local/session storage usage
            storage_found, storage_evidence = detect_local_session_storage(page)
            if storage_found:
                add_violation(
                    "local_session_storage",
                    "Client-side Storage (localStorage/sessionStorage) Usage",
                    "Medium",
                    ("Site stores keys in localStorage/sessionStorage which can persist identifiers client-side and be used for tracking."),
                    ("Do not persist personal identifiers in localStorage. Use server-side sessions or store anonymized tokens."),
                    storage_evidence
                )

            # Detector 9: personal data collection forms (PII)
            pii_found, pii_evd = detect_personal_data_forms(html_combined)
            if pii_found:
                add_violation(
                    "collecting_pii",
                    "Personal Information (PII) Collection Detected",
                    "High",
                    ("Forms or input fields suggest collection of PII (email, name, phone). Ensure lawful basis and consent for processing."),
                    ("Display purpose and lawful basis near forms, include opt-in checkboxes and store consent receipts (timestamp, scope)."),
                    pii_evd
                )

            # Detector 10: missing access / deletion mechanisms (heuristic)
            access_present = any(k in (html_combined) for k in ["access my data", "download my data", "request my data", "right to be forgotten", "delete my data"])
            if not access_present:
                add_violation(
                    "no_access_or_deletion_mechanism",
                    "No Data Access/Deletion Mechanism Detected",
                    "High",
                    ("No clear mechanism found for users to access or delete their personal data. GDPR/CCPA mandate access and deletion rights."),
                    ("Implement easy-to-use pages/forms for data access and deletion requests, with verification and confirmation workflows."),
                    {"access_found": access_present}
                )

            # Detector 11: email marketing without explicit consent (heuristic)
            if ("newsletter" in html_combined or "subscribe" in html_combined) and not any(k in html_combined for k in ["consent", "i agree", "opt-in", "subscribe me"]):
                add_violation(
                    "email_marketing_without_consent",
                    "Email Marketing / Newsletter Without Clear Consent",
                    "Medium",
                    ("Newsletter or subscription forms detected without explicit consent language or opt-in checkbox."),
                    ("Use unchecked opt-in checkboxes and store consent logs for marketing communications. Provide unsubscribe links."),
                    {}
                )

            # Detector 12: dark patterns (consent UI)
            if ("accept all" in html_combined and "reject" not in html_combined) or ("accept" in html_combined and "decline" not in html_combined):
                add_violation(
                    "dark_pattern_consent_ui",
                    "Potential Dark Pattern in Consent UI",
                    "High",
                    ("UI appears to nudge or coerce users into accepting cookies (e.g., only 'Accept' visible or prominent)."),
                    ("Redesign UI to present choices neutrally; ensure equal emphasis and visibility for reject and accept."),
                    {}
                )

            # Detector 13: insecure transport (http resources)
            http_found, http_evd = detect_http_resources(request_urls_snapshot)
            if http_found:
                add_violation(
                    "insecure_transport",
                    "Insecure HTTP Resources Detected",
                    "Critical",
                    ("The page loads resources or makes requests over HTTP which can lead to data interception and mixed-content issues."),
                    ("Serve all resources over HTTPS, enable HSTS, and use 'upgrade-insecure-requests' CSP directive."),
                    http_evd
                )

            # Detector 14: third-party data sharing not disclosed (heuristic)
            third_party_disclosed = privacy_analysis.get("third_party", False) if privacy_info.get("found") else False
            if not third_party_disclosed and trackers_found:
                add_violation(
                    "third_party_sharing_undisclosed",
                    "Third-Party Data Sharing Not Disclosed",
                    "High",
                    ("Trackers detected but privacy policy does not describe third-party sharing or processors."),
                    ("Document all third-party processors, purposes and ensure contracts (DPAs). Communicate this in privacy policy."),
                    {"trackers": trackers_evidence, "privacy_disclosed": third_party_disclosed}
                )

            # Detector 15: analytics not anonymized
            ga_anon_ok, ga_anon_info = detect_analytics_anonymize(html_combined)
            if ga_anon_info.get("analytics_present") and not ga_anon_ok:
                add_violation(
                    "analytics_without_anonymization",
                    "Analytics Not Configured with IP Anonymization",
                    "Medium",
                    ("Google Analytics present without `anonymize_ip` enabled which may result in IP-based identification."),
                    ("Enable anonymize_ip in Google Analytics or adopt privacy-first analytics solutions."),
                    ga_anon_info
                )

            # Detector 16: excessive cookie count (>20)
            excessive_cookie_flag = len(final_cookies) > 20
            if excessive_cookie_flag:
                add_violation(
                    "excessive_cookie_count",
                    "Excessive Cookie Count",
                    "Low",
                    ("More than 20 cookies set which may indicate many trackers or redundant cookies."),
                    ("Audit cookies, consolidate analytics tags, remove duplicates and unnecessary cookies."),
                    {"cookie_count": len(final_cookies)}
                )

            # Detector 17: missing do-not-sell / CCPA opt-out (heuristic)
            do_not_sell_present = False
            try:
                do_not_sell_present = any("do not sell" in (a.inner_text() or "").lower() or "do-not-sell" in (a.get_attribute("href") or "") for a in page.query_selector_all("a"))
            except Exception:
                pass
            if not do_not_sell_present:
                add_violation(
                    "missing_do_not_sell",
                    "Missing 'Do Not Sell' / CCPA Opt-Out Link",
                    "High",
                    ("No clear 'Do Not Sell My Personal Information' opt-out link was found. CCPA requires opt-out for selling personal info."),
                    ("Add a footer link to a CCPA opt-out page and implement opt-out processing for CA consumers."),
                    {"do_not_sell_present": do_not_sell_present}
                )

            # Detector 18: missing retention policy
            if privacy_info.get("found") and not privacy_analysis.get("retention"):
                add_violation(
                    "missing_retention_policy",
                    "Privacy Policy Missing Retention Information",
                    "Medium",
                    ("Privacy policy does not mention data retention periods for collected personal data."),
                    ("Specify retention periods (or criteria for retention) in the privacy policy and consider automated deletion."),
                    {"privacy_url": privacy_info.get("privacy_url")}
                )

            # Detector 19: missing withdraw consent mechanism
            if not any(k in html_combined for k in ["manage consent", "cookie settings", "privacy settings", "withdraw consent"]):
                add_violation(
                    "missing_withdraw_consent",
                    "No Withdraw/Manage Consent Mechanism Detected",
                    "Medium",
                    ("No persistent mechanism found to let users withdraw or manage previously given consent."),
                    ("Provide a persistent 'Manage Consent' or 'Privacy Settings' control accessible from the site footer."),
                    {}
                )

            # Detector 20: missing data access / deletion flows (already covered earlier) - refine severity if policy missing
            # (Already added 'no_access_or_deletion_mechanism' earlier.)

            # 6) Build metadata to return
            result["metadata"] = {
                "initial_cookie_count": len(initial_cookies),
                "final_cookie_count": len(final_cookies),
                "initial_cookie_names": initial_cookie_names,
                "scripts": scripts_snapshot[:200],
                "requests_sample": request_urls_snapshot[:200],
                "console_logs_sample": console_logs[:50],
                "privacy_info": privacy_info,
                "privacy_analysis": privacy_analysis,
                "local_session_storage": storage_details,
            }

            # Optionally save screenshot for evidence
            if save_screenshot:
                try:
                    host = urlparse(result["final_url"]).hostname or "site"
                    path = SCREENSHOT_PATH_TEMPLATE.format(host=host)
                    page.screenshot(path=path, full_page=True)
                    result["metadata"]["screenshot"] = path
                except Exception:
                    pass

            # Compute a simple score: start 100, subtract 5/10 per violation weighted by severity
            severity_weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
            score = 100
            for v in result["violations"]:
                weight = severity_weights.get(v.get("severity", "Medium"), 5)
                score -= weight
            result["score"] = max(0, score)
            return result

    except Exception as exc:
        traceback.print_exc()
        return {"url": url, "error": str(exc), "violations": [], "metadata": {}}

# ---------------------------
# CLI runner
# ---------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python advanced_scanner.py https://example.com")
        sys.exit(1)
    target = sys.argv[1]
    out = powerful_scan(target, save_screenshot=SAVE_SCREENSHOT)
    print(json.dumps(out, indent=2))
