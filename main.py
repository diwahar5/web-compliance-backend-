# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from advanced_scanner import powerful_scan
from snippet_registry import FIX_SNIPPETS
import logging

# -------------------------------------------
# ✅ CONFIGURATION
# -------------------------------------------
app = FastAPI(
    title="Web Compliance API",
    description="API to scan websites for GDPR/CCPA violations and provide code fixes.",
    version="2.0.0"
)

# Enable frontend access (adjust for your environment)
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://web-compliance-tool.vercel.app",
    "http://192.168.56.1:3000",
    "http://10.210.108.245:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all if not specified
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enable logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# -------------------------------------------
# ✅ ROOT ENDPOINT
# -------------------------------------------
@app.get("/")
def root():
    return {"message": "✅ Web Compliance API is running successfully."}


# -------------------------------------------
# ✅ WEBSITE SCAN ENDPOINT
# -------------------------------------------
@app.get("/scan")
def scan(url: str):
    """
    Scans a website URL for privacy violations.
    Example: /scan?url=https://example.com
    """
    logging.info(f"🕵️‍♂️ Scanning URL: {url}")
    try:
        result = powerful_scan(url)
        return {"status": "success", "data": result}
    except Exception as e:
        logging.error(f"❌ Scan failed: {str(e)}")
        return {"status": "error", "message": str(e)}


# -------------------------------------------
# ✅ FIX SNIPPET ENDPOINT (SMART MATCHING)
# -------------------------------------------
@app.get("/fix")
def get_fix(violation_id: str):
    """
    Returns an HTML + React code snippet to fix a detected violation.
    Example: /fix?violation_id=cookies_before_consent
    """

    normalized_id = violation_id.strip().lower().replace(" ", "_")
    logging.info(f"📡 Requested snippet for violation ID: {normalized_id}")

    # Try exact match
    snippet = FIX_SNIPPETS.get(normalized_id)

    # Try fuzzy match (partial substring match)
    if not snippet:
        for key in FIX_SNIPPETS:
            if normalized_id in key or key in normalized_id:
                logging.warning(f"⚠️ Fuzzy matched '{normalized_id}' to '{key}'")
                snippet = FIX_SNIPPETS[key]
                break

    # Return default snippet if nothing found
    if not snippet:
        logging.warning(f"⚠️ No snippet found for '{violation_id}'")
        return {
            "status": "success",
            "data": {
                "title": f"No snippet found for '{violation_id}'",
                "html": "<!-- No snippet available -->",
                "react": f"// No snippet available for violation ID: {violation_id}"
            }
        }

    # Return valid snippet
    logging.info(f"✅ Returning fix snippet for '{violation_id}'")
    return {"status": "success", "data": snippet}
