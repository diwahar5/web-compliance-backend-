"""
advanced_scanner.py — Powerful GDPR/CCPA Web Compliance Scanner
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
NAV_TIMEOUT = 120_000
WAIT_AFTER_LOAD = 3.0
RETRY_ATTEMPTS = 2
SAVE_SCREENSHOT = True
SCREENSHOT_PATH_TEMPLATE = "scan_{host}.png"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
)

# ---------------------------
# Helper utilities
# ---------------------------
def _safe_goto(page, url: str, timeout: int = NAV_TIMEOUT) -> None:
    last_exc = None
    for _ in range(RETRY_ATTEMPTS):
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            page.wait_for_timeout(int(WAIT_AFTER_LOAD * 1000))
            return
        except Exception as e:
            last_exc = e
            time.sleep(1)
    raise last_exc


def _find_links(page, patterns: List[str]) -> List[str]:
    found = []
    try:
        for a in page.query_selector_all("a"):
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
# Heuristic detectors
# ---------------------------
def detect_consent_banner(html: str, page) -> Tuple[bool, dict]:
    patterns = [
        "cookie consent", "accept cookies", "cookie banner", "cookie settings",
        "manage cookies", "we use cookies", "accept all"
    ]
    found = any(p in html for p in patterns)
    details = {"method": "keyword", "matched": [p for p in patterns if p in html]}

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
        buttons = page.query_selector_all("button, a, input[type='button'], input[type='submit']")
        seen = []
        for el in buttons:
            t = (el.inner_text() or "").lower()
            seen.append(t)
            if any(k in t for k in ["reject", "deny", "decline", "manage", "cookie settings"]):
                return True, {"matched_text": t}
        return False, {"sample_texts": seen[:10]}
    except Exception:
        return False, {}


def detect_fingerprinting(html: str, scripts: List[str], page) -> Tuple[bool, dict]:
    hits = []
    fp_libs = [
        "fingerprintjs", "fingerprint2", "clientjs", "canvas", "webgl",
        "audiocontext", "devicememory", "navigator.hardwareconcurrency"
    ]

    for lib in fp_libs:
        if lib in html:
            hits.append({"source": "html", "matched": lib})

    for s in scripts:
        if s and any(lib in s.lower() for lib in fp_libs):
            hits.append({"source": "script_src", "matched": s})

    try:
        canvas_uses = page.evaluate("""() => {
            try {
                const scripts = Array.from(document.scripts).map(s => s.textContent || "").join(" ");
                return /toDataURL\\(|getContext\\('webgl'\\)/i.test(scripts);
            } catch (e) { return false; }
        }""")
        if canvas_uses:
            hits.append({"source": "runtime", "matched": "canvas/webgl usage detected"})
    except Exception:
        pass

    return bool(hits), {"hits": hits}


def detect_local_session_storage(page) -> Tuple[bool, dict]:
    try:
        local_keys = page.evaluate("() => Object.keys(localStorage || {})")
        session_keys = page.evaluate("() => Object.keys(sessionStorage || {})")
        return bool(local_keys or session_keys), {
            "localStorage": local_keys,
            "sessionStorage": session_keys
        }
    except Exception:
        return False, {}


def detect_cookies_before_consent(initial_cookies: List[dict], post_cookies: List[dict]):
    initial_persistent = [c for c in initial_cookies if not c.get("session", False)]
    evidence = {
        "initial_count": len(initial_cookies),
        "initial_persistent": [c.get("name") for c in initial_persistent]
    }
    return bool(initial_persistent), evidence


def detect_insecure_cookies(cookies: List[dict]):
    insecure = [
        {
            "name": c.get("name"),
            "secure": c.get("secure"),
            "sameSite": c.get("sameSite")
        }
        for c in cookies
        if not c.get("secure", False) or c.get("sameSite") in (None, "None", "")
    ]
    return bool(insecure), {"insecure": insecure}


def detect_http_resources(request_urls: List[str]):
    http_resources = [r for r in request_urls if r.startswith("http://")]
    return bool(http_resources), {"http_resources": http_resources[:20]}


def detect_third_party_trackers(scripts, request_urls):
    known = ["google-analytics", "doubleclick", "facebook", "ads", "hotjar",
             "tiktok", "segment", "mixpanel", "fullstory", "intercom"]
    hits = []

    for s in scripts:
        if s:
            low = s.lower()
            for k in known:
                if k in low:
                    hits.append({"script": s, "matched": k})

    for r in request_urls:
        low = r.lower()
        for k in known:
            if k in low:
                hits.append({"request": r, "matched": k})

    return bool(hits), {"hits": hits}


def detect_personal_data_forms(html: str):
    patterns = ["name=", "email", "phone", "address", "ssn", "birth", "dob"]
    matches = [p for p in patterns if p in html]
    return bool(matches), {"matched": matches}


def detect_privacy_policy_and_analyze(page, base_url):
    result = {"found": False, "privacy_url": None, "privacy_text_snippet": None}
    analysis = {
        "retention": False,
        "third_party": False,
        "delete": False,
        "access": False,
        "do_not_sell": False
    }

    try:
        links = page.query_selector_all("a")
        candidates = []

        for a in links:
            href = a.get_attribute("href") or ""
            text = (a.inner_text() or "").lower()
            if "privacy" in href.lower() or "privacy" in text:
                candidates.append(href)

        if candidates:
            raw = candidates[0]
            privacy_url = raw if raw.startswith("http") else urljoin(base_url, raw)
            result["found"] = True
            result["privacy_url"] = privacy_url

            try:
                page.goto(privacy_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(1000)
                phtml = (page.content() or "").lower()
                result["privacy_text_snippet"] = phtml[:4000]

                analysis["retention"] = any(k in phtml for k in ["retention", "retain", "period"])
                analysis["third_party"] = any(k in phtml for k in ["third party", "vendors", "partners"])
                analysis["delete"] = any(k in phtml for k in ["delete my", "erase", "forgotten"])
                analysis["access"] = any(k in phtml for k in ["access my data", "download"])
                analysis["do_not_sell"] = "do not sell" in phtml

            except Exception:
                pass

    except Exception:
        pass

    return result, analysis


def detect_analytics_anonymize(html: str):
    if "google-analytics" in html or "gtag(" in html:
        if "anonymize_ip" in html:
            return True, {"anonymize_detected": True}
        return False, {"analytics_present": True, "anonymize_detected": False}
    return False, {"analytics_present": False}

# ---------------------------
# Main scanner
# ---------------------------
def powerful_scan(url: str, save_screenshot: bool = SAVE_SCREENSHOT) -> Dict[str, Any]:
    result = {
        "url": url,
        "final_url": None,
        "score": 100,
        "violations": [],
        "metadata": {}
    }

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=USER_AGENT,
                viewport={"width": 1280, "height": 800}
            )

            page = context.new_page()

            request_urls = []
            response_statuses = []
            console_logs = []
            scripts_collected = []

            def on_request(req):
                try:
                    request_urls.append(req.url)
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

            # ---- navigation ----
            _safe_goto(page, url)
            result["final_url"] = page.url
            base_url = result["final_url"]

            # ---- HTML and resources ----
            html = (page.content() or "").lower()
            initial_cookies = context.cookies()

            scripts_srcs = scripts_collected or [
                s.get_attribute("src")
                for s in page.query_selector_all("script")
                if s.get_attribute("src")
            ]

            inline_scripts = []
            try:
                for s in page.query_selector_all("script"):
                    try:
                        txt = s.inner_text()
                        if txt and len(txt) < 50000:
                            inline_scripts.append(txt[:2000])
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                html_combined = html + " " + " ".join(inline_scripts)
            except Exception:
                html_combined = html

            local_session_present, storage_details = detect_local_session_storage(page)

            # ---- Detect consent buttons ----
            consent_buttons = {"accept": None, "reject": None, "manage": None}
            try:
                for b in page.query_selector_all("button, a, input[type='button'], input[type='submit']"):
                    txt = (b.inner_text() or "").lower()
                    if not consent_buttons["accept"] and any(k in txt for k in ["accept all", "accept", "agree"]):
                        consent_buttons["accept"] = b
                    if not consent_buttons["reject"] and any(k in txt for k in ["reject", "decline", "deny"]):
                        consent_buttons["reject"] = b
                    if not consent_buttons["manage"] and any(k in txt for k in ["manage", "preferences", "cookie settings"]):
                        consent_buttons["manage"] = b
            except Exception:
                pass

            initial_cookie_names = [c.get("name") for c in initial_cookies]

            # ---- simulate consent actions ----
            post_reject_cookies = []
            try:
                if consent_buttons["reject"]:
                    consent_buttons["reject"].click()
                    page.wait_for_timeout(1000)
                    post_reject_cookies = context.cookies()
                elif consent_buttons["manage"]:
                    consent_buttons["manage"].click()
                    page.wait_for_timeout(1000)
                    post_reject_cookies = context.cookies()
            except Exception:
                pass

            post_accept_cookies = []
            try:
                if consent_buttons["accept"]:
                    consent_buttons["accept"].click()
                    page.wait_for_timeout(1500)
                    post_accept_cookies = context.cookies()
            except Exception:
                pass

            # ---- privacy policy ----
            privacy_info, privacy_analysis = detect_privacy_policy_and_analyze(page, base_url)

            final_cookies = context.cookies()
            request_urls_snapshot = list(dict.fromkeys(request_urls))
            scripts_snapshot = scripts_srcs or scripts_collected

            # ---- Add violation helper ----
            def add_violation(vid, title, severity, description, recommendation, evidence=None):
                result["violations"].append({
                    "id": vid,
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation,
                    "evidence": evidence or {}
                })

            # ---- Detectors ----
            found_banner, banner_details = detect_consent_banner(html_combined, page)
            if not found_banner:
                add_violation(
                    "missing_consent_banner",
                    "Missing Cookie Consent Banner",
                    "High",
                    "No consent banner detected.",
                    "Add a proper GDPR-compliant cookie banner.",
                    {"details": banner_details}
                )

            has_reject, reject_details = detect_reject_option(page)
            if not has_reject:
                add_violation(
                    "no_reject_option",
                    "No Reject Option",
                    "High",
                    "Consent UI lacks reject/decline option.",
                    "Add an equally-visible reject or manage option.",
                    reject_details
                )

            cookies_before, cookies_before_evidence = detect_cookies_before_consent(initial_cookies, post_accept_cookies or final_cookies)
            if cookies_before:
                add_violation(
                    "cookies_before_consent",
                    "Cookies Set Before Consent",
                    "Critical",
                    "Non-essential cookies appear before user consent.",
                    "Block all non-essential cookies until consent.",
                    cookies_before_evidence
                )

            insecure_found, insecure_evd = detect_insecure_cookies(final_cookies)
            if insecure_found:
                add_violation(
                    "insecure_cookies",
                    "Insecure Cookies Detected",
                    "Critical",
                    "Cookies missing Secure/SameSite attributes.",
                    "Use Secure, HttpOnly, and SameSite on cookies.",
                    insecure_evd
                )

            if not privacy_info.get("found"):
                add_violation(
                    "missing_privacy_policy",
                    "Missing Privacy Policy",
                    "High",
                    "Privacy policy link not detected.",
                    "Add a footer privacy policy link.",
                    {"privacy_link_found": False}
                )
            else:
                missing_parts = []
                if not privacy_analysis["retention"]:
                    missing_parts.append("retention_period")
                if not privacy_analysis["third_party"]:
                    missing_parts.append("third_party_disclosure")
                if not privacy_analysis["delete"]:
                    missing_parts.append("delete_info")
                if not privacy_analysis["access"]:
                    missing_parts.append("access_info")
                if not privacy_analysis["do_not_sell"]:
                    missing_parts.append("do_not_sell")

                if missing_parts:
                    add_violation(
                        "privacy_policy_incomplete",
                        "Privacy Policy Missing Key Disclosures",
                        "Medium",
                        "Privacy policy missing required disclosures.",
                        "Update privacy policy.",
                        {"missing_sections": missing_parts}
                    )

            trackers_found, trackers_evd = detect_third_party_trackers(scripts_snapshot, request_urls_snapshot)
            if trackers_found:
                add_violation(
                    "third_party_trackers",
                    "Third-Party Trackers Detected",
                    "Medium",
                    "External trackers detected.",
                    "Load trackers only after consent.",
                    trackers_evd
                )

            fp_found, fp_evd = detect_fingerprinting(html_combined, scripts_snapshot, page)
            if fp_found:
                add_violation(
                    "fingerprinting",
                    "Browser Fingerprinting Detected",
                    "Critical",
                    "Fingerprinting activity detected.",
                    "Avoid fingerprinting unless required with consent.",
                    fp_evd
                )

            storage_found, storage_evd = detect_local_session_storage(page)
            if storage_found:
                add_violation(
                    "local_session_storage",
                    "Client Storage Detected",
                    "Medium",
                    "localStorage/sessionStorage used.",
                    "Avoid storing identifiers in client storage.",
                    storage_evd
                )

            pii_found, pii_evd = detect_personal_data_forms(html_combined)
            if pii_found:
                add_violation(
                    "collecting_pii",
                    "PII Collection Detected",
                    "High",
                    "Forms collecting PII found.",
                    "Add consent & legal basis near forms.",
                    pii_evd
                )

            if not any(k in html_combined for k in ["access my data", "delete my data", "request my data"]):
                add_violation(
                    "no_access_or_deletion_mechanism",
                    "Missing User Rights Interface",
                    "High",
                    "No access/deletion mechanism found.",
                    "Add pages/forms for GDPR/CCPA rights."
                )

            ga_ok, ga_info = detect_analytics_anonymize(html_combined)
            if ga_info.get("analytics_present") and not ga_ok:
                add_violation(
                    "analytics_without_anonymization",
                    "Analytics Not Anonymized",
                    "Medium",
                    "GA present without anonymize_ip.",
                    "Enable anonymize_ip."
                )

            http_found, http_evd = detect_http_resources(request_urls_snapshot)
            if http_found:
                add_violation(
                    "insecure_transport",
                    "HTTP Resources Loaded",
                    "Critical",
                    "Non-HTTPS resources detected.",
                    "Serve all resources over HTTPS.",
                    http_evd
                )

            if privacy_info.get("found") and trackers_found and not privacy_analysis["third_party"]:
                add_violation(
                    "third_party_sharing_undisclosed",
                    "Third-Party Sharing Not Disclosed",
                    "High",
                    "Trackers detected but not disclosed in privacy policy.",
                    "Document all third-party processors.",
                    trackers_evd
                )

            excessive_cookie_flag = len(final_cookies) > 20
            if excessive_cookie_flag:
                add_violation(
                    "excessive_cookie_count",
                    "Excessive Cookie Count",
                    "Low",
                    "More than 20 cookies set.",
                    "Audit and reduce unnecessary cookies.",
                    {"cookie_count": len(final_cookies)}
                )

            do_not_sell_present = False
            try:
                do_not_sell_present = any(
                    "do not sell" in (a.inner_text() or "").lower() or
                    "do-not-sell" in (a.get_attribute("href") or "").lower()
                    for a in page.query_selector_all("a")
                )
            except Exception:
                pass

            if not do_not_sell_present:
                add_violation(
                    "missing_do_not_sell",
                    "Missing Do-Not-Sell Link",
                    "High",
                    "CCPA opt-out link missing.",
                    "Add a 'Do Not Sell My Personal Information' link."
                )

            if privacy_info.get("found") and not privacy_analysis["retention"]:
                add_violation(
                    "missing_retention_policy",
                    "Missing Retention Policy",
                    "Medium",
                    "Privacy policy lacks retention details.",
                    "Add retention periods."
                )

            if not any(k in html_combined for k in ["manage consent", "withdraw consent"]):
                add_violation(
                    "missing_withdraw_consent",
                    "Missing Consent Withdrawal",
                    "Medium",
                    "No mechanism to withdraw consent.",
                    "Add persistent 'Manage Consent' UI."
                )

            # ---- Metadata ----
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

            if save_screenshot:
                try:
                    host = urlparse(result["final_url"]).hostname or "site"
                    path = SCREENSHOT_PATH_TEMPLATE.format(host=host)
                    page.screenshot(path=path, full_page=True)
                    result["metadata"]["screenshot"] = path
                except Exception:
                    pass

            severity_weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
            score = 100
            for v in result["violations"]:
                score -= severity_weights.get(v["severity"], 5)
            result["score"] = max(0, score)

            return result

    except Exception as exc:
        traceback.print_exc()
        return {"url": url, "error": str(exc), "violations": [], "metadata": {}}

# ---------------------------
# CLI
# ---------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python advanced_scanner.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    out = powerful_scan(target, save_screenshot=SAVE_SCREENSHOT)
    print(json.dumps(out, indent=2))
