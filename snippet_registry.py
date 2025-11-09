"""
snippet_registry.py
---------------------------------
Static registry mapping GDPR/CCPA compliance violations to their
recommended code fixes in both HTML and React formats.
Used by /fix endpoint in main.py.
"""

FIX_SNIPPETS = {
    # 1️⃣ MISSING CONSENT BANNER
    "missing_consent_banner": {
        "title": "Add a Cookie Consent Banner",
        "html": """<div id="cookie-banner" role="dialog">
  <p>We use cookies to improve your experience. <a href="/privacy">Privacy Policy</a></p>
  <button id="accept">Accept</button>
  <button id="reject">Reject</button>
</div>
<script>
document.getElementById('accept').onclick = () => {
  localStorage.setItem('cookie-consent', 'accepted');
  document.getElementById('cookie-banner').remove();
}
document.getElementById('reject').onclick = () => {
  localStorage.setItem('cookie-consent', 'rejected');
  document.getElementById('cookie-banner').remove();
}
</script>""",
        "react": """import React from 'react';
export default function CookieConsent(){
  const accept = () => localStorage.setItem('cookie-consent','accepted');
  const reject = () => localStorage.setItem('cookie-consent','rejected');
  return (
    <div className='fixed bottom-4 left-0 right-0 mx-auto max-w-md p-4 bg-gray-900 text-white rounded-lg'>
      <p>We use cookies to enhance your experience. <a href='/privacy' className='underline'>Privacy Policy</a></p>
      <div className='mt-2 space-x-2'>
        <button onClick={accept} className='bg-green-600 px-3 py-1 rounded'>Accept</button>
        <button onClick={reject} className='bg-red-600 px-3 py-1 rounded'>Reject</button>
      </div>
    </div>
  );
}"""
    },

    # 2️⃣ NO REJECT BUTTON
    "no_reject_option": {
        "title": "Add a Reject Button to Consent UI",
        "html": """<div id="cookie-banner">
  <p>We use cookies for analytics and personalization.</p>
  <button>Accept</button>
  <button>Reject</button>
  <a href="/cookie-preferences">Manage Preferences</a>
</div>""",
        "react": """export default function ConsentUI(){
  return (
    <div>
      <p>We use cookies for analytics and personalization.</p>
      <button>Accept</button>
      <button>Reject</button>
      <a href='/cookie-preferences'>Manage Preferences</a>
    </div>
  );
}"""
    },

    # 3️⃣ COOKIES BEFORE CONSENT
    "cookies_before_consent": {
        "title": "Delay Cookie Loading Until Consent",
        "html": """<script>
function loadAnalytics(){
  if(localStorage.getItem('cookie-consent') === 'accepted'){
    const s = document.createElement('script');
    s.src = 'https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID';
    document.head.appendChild(s);
  }
}
</script>""",
        "react": """export function loadAnalyticsIfConsent(){
  if(localStorage.getItem('cookie-consent') === 'accepted'){
    const s = document.createElement('script');
    s.src = 'https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID';
    document.head.appendChild(s);
  }
}"""
    },

    # 4️⃣ INSECURE COOKIES
    "insecure_cookies": {
        "title": "Set Secure and HttpOnly Cookies",
        "html": """<!-- Example: Secure cookie configuration -->
Set-Cookie: session_id=abc123; Secure; HttpOnly; SameSite=Strict""",
        "react": """// Express.js server example
res.cookie('session_id', token, {
  secure: true,
  httpOnly: true,
  sameSite: 'Strict'
});"""
    },

    # 5️⃣ MISSING PRIVACY POLICY
    "missing_privacy_policy": {
        "title": "Add a Privacy Policy Link",
        "html": """<footer><a href="/privacy">Privacy Policy</a></footer>""",
        "react": """export default function Footer(){
  return (<footer><a href='/privacy'>Privacy Policy</a></footer>);
}"""
    },

    # 6️⃣ MISSING DO-NOT-SELL LINK
    "missing_do_not_sell": {
        "title": "Add 'Do Not Sell My Info' Link",
        "html": """<footer><a href="/do-not-sell">Do Not Sell My Personal Information</a></footer>""",
        "react": """export default function DoNotSell(){
  return (<a href='/do-not-sell'>Do Not Sell My Personal Information</a>);
}"""
    },

    # 7️⃣ THIRD-PARTY TRACKERS
    "third_party_trackers": {
        "title": "Load Third-Party Trackers After Consent",
        "html": """<script>
function loadTracker(src){
  if(localStorage.getItem('cookie-consent')==='accepted'){
    const s=document.createElement('script');
    s.src=src;
    document.head.appendChild(s);
  }
}
</script>""",
        "react": """export function loadTracker(src:string){
  if(localStorage.getItem('cookie-consent')==='accepted'){
    const s=document.createElement('script');
    s.src=src;
    document.head.appendChild(s);
  }
}"""
    },

    # 8️⃣ FINGERPRINTING
    "fingerprinting": {
        "title": "Disable Browser Fingerprinting",
        "html": """<!-- Remove any fingerprinting libraries like FingerprintJS -->
<!-- Avoid using canvas.toDataURL, AudioContext, or WebGL for identification -->""",
        "react": """console.warn("Avoid using browser fingerprinting techniques (e.g., canvas/WebGL/audio tracking).");"""
    },

    # 9️⃣ LOCALSTORAGE WITHOUT CONSENT
    "local_storage_use": {
        "title": "Avoid Unconsented LocalStorage Usage",
        "html": """<script>
if(!localStorage.getItem('cookie-consent')){
  localStorage.clear();
}
</script>""",
        "react": """export function safeStorage(key:string,val:string){
  if(localStorage.getItem('cookie-consent')==='accepted'){
    localStorage.setItem(key,val);
  }
}"""
    },

    # 🔟 MISSING DATA ACCESS
    "missing_data_access_option": {
        "title": "Add 'Request My Data' Form",
        "html": """<form action="/requests/access" method="post">
  <input type="email" name="email" required placeholder="Email">
  <button type="submit">Request My Data</button>
</form>""",
        "react": """export default function DataAccessForm(){
  return (
    <form action='/requests/access' method='post'>
      <input name='email' required placeholder='Email'/>
      <button>Request My Data</button>
    </form>
  );
}"""
    },

    # 11️⃣ MISSING DATA DELETION FORM
    "missing_data_deletion": {
        "title": "Add 'Delete My Data' Form",
        "html": """<form action="/requests/delete" method="post">
  <input type="email" name="email" required placeholder="Email">
  <button type="submit">Delete My Data</button>
</form>""",
        "react": """export default function DataDeleteForm(){
  return (
    <form action='/requests/delete' method='post'>
      <input name='email' required placeholder='Email'/>
      <button>Delete My Data</button>
    </form>
  );
}"""
    },

    # 12️⃣ MISSING RETENTION POLICY
    "missing_retention_policy": {
        "title": "Add Data Retention Statement",
        "html": """<section><h3>Data Retention</h3>
<p>We keep user data for 24 months or until deletion request.</p></section>""",
        "react": """export default function RetentionInfo(){
  return (
    <section><h3>Data Retention</h3>
    <p>We retain data for 24 months after last use.</p></section>
  );
}"""
    },

    # 13️⃣ MISSING MANAGE CONSENT LINK
    "missing_withdraw_consent": {
        "title": "Add 'Manage Consent' Option",
        "html": """<a href="/privacy#manage">Manage Consent</a>""",
        "react": """export default function ManageConsentLink(){
  return (<a href='/privacy#manage'>Manage Consent</a>);
}"""
    },

    # 14️⃣ PII WITHOUT CONSENT
    "collecting_pii": {
        "title": "Request PII Only With Consent",
        "html": """<form>
  <label>Email <input name="email" type="email" required></label>
  <label><input type="checkbox" name="consent" required> I consent</label>
  <button>Submit</button>
</form>""",
        "react": """export default function Signup(){
  return (
    <form>
      <label>Email <input type='email' required/></label>
      <label><input type='checkbox' required/> I consent</label>
      <button>Submit</button>
    </form>
  );
}"""
    },

    # 15️⃣ EMAIL MARKETING WITHOUT CONSENT
    "email_marketing_without_consent": {
        "title": "Add Consent Checkbox to Newsletter",
        "html": """<form>
  <input name="email" type="email" required placeholder="Email">
  <label><input type="checkbox" required> I consent to marketing emails</label>
  <button>Subscribe</button>
</form>""",
        "react": """export default function NewsletterForm(){
  return (
    <form>
      <input name='email' type='email' required placeholder='Email'/>
      <label><input type='checkbox' required/> I consent to receive emails</label>
      <button>Subscribe</button>
    </form>
  );
}"""
    },

    # 16️⃣ DARK PATTERN CONSENT UI
    "dark_pattern_consent_ui": {
        "title": "Ensure Neutral Consent Design",
        "html": """<div>
  <button id="accept">Accept</button>
  <button id="reject">Reject</button>
</div>""",
        "react": """export default function NeutralUI(){
  return (<div><button>Accept</button><button>Reject</button></div>);
}"""
    },

    # 17️⃣ INSECURE TRANSPORT
    "insecure_transport": {
        "title": "Force HTTPS for All Requests",
        "html": """<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">""",
        "react": """export const enforceHttps = `
app.use((req,res,next)=>{
  if(!req.secure)
    return res.redirect('https://' + req.headers.host + req.url);
  next();
});
`;"""
    },

    # 18️⃣ THIRD-PARTY DATA SHARING
    "third_party_data_sharing": {
        "title": "Disclose Third-Party Processors",
        "html": """<section>
  <h3>Third-Party Processors</h3>
  <p>We share limited data with analytics.example.com under a DPA agreement.</p>
</section>""",
        "react": """export default function ThirdPartyDisclosure(){
  return (
    <section>
      <h3>Third-Party Processors</h3>
      <p>We share limited data with analytics.example.com under DPA.</p>
    </section>
  );
}"""
    },

    # 19️⃣ ANALYTICS WITHOUT ANONYMIZATION
    "analytics_without_anonymization": {
        "title": "Enable IP Anonymization in Google Analytics",
        "html": """<script>
gtag('config', 'GA_MEASUREMENT_ID', {'anonymize_ip': true});
</script>""",
        "react": """export const gaAnonymizeExample = `
gtag('config', 'GA_MEASUREMENT_ID', {'anonymize_ip': true});
`;
"""
    },

    # 20️⃣ EXCESSIVE COOKIE COUNT
    "excessive_cookie_count": {
        "title": "Reduce Number of Cookies Used",
        "html": """<p>Audit cookies regularly, remove duplicates, and minimize third-party trackers.</p>""",
        "react": """export default function CookieAuditNote(){
  return (<p>Audit cookies regularly and reduce non-essential ones.</p>);
}"""
    }
}
