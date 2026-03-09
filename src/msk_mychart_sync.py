#!/usr/bin/env python3
"""
MSK MyChart FHIR Document Sync
Automatically downloads clinical documents, notes, labs, medications,
and letters from MSK MyChart using Epic's FHIR R4 API.

Requirements:
    pip install requests
"""

import argparse
import os
import json
import ssl
import time
import base64
import hashlib
import secrets
import tempfile
import webbrowser
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime

import requests

# ── Configuration ────────────────────────────────────────────────────────────

CLIENT_ID_PROD     = "foo"
CLIENT_ID_SANDBOX  = "bar"
FHIR_BASE_PROD     = "https://epicproxy.et1353.epichosted.com/APIPROXYPRD/api/FHIR/R4"
FHIR_BASE_SANDBOX  = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4"
REDIRECT_URI       = "https://localhost:3000/callback"
OUTPUT_DIR         = Path("~/msk_records").expanduser()
TOKEN_FILE         = Path("~/.msk_mychart_token.json").expanduser()

# Defaults — overridden by --sandbox
FHIR_BASE = FHIR_BASE_PROD
CLIENT_ID = CLIENT_ID_PROD

# FHIR scopes needed for all document types
SCOPES = " ".join([
    "launch/patient",
    "patient/Patient.read",
    "patient/DocumentReference.read",
    "patient/DiagnosticReport.read",
    "patient/Observation.read",
    "patient/MedicationRequest.read",
    "patient/Encounter.read",
    "offline_access",
    "openid",
    "fhirUser",
])

# ── PKCE helpers ─────────────────────────────────────────────────────────────

def generate_pkce():
    """Generate PKCE code verifier and challenge (required by Epic)."""
    verifier  = secrets.token_urlsafe(64)
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge

# ── Self-signed cert for localhost HTTPS ──────────────────────────────────────

def _generate_self_signed_cert():
    """Generate a temporary self-signed cert for the localhost callback server."""
    import subprocess
    cert_dir = tempfile.mkdtemp()
    certfile = os.path.join(cert_dir, "cert.pem")
    keyfile  = os.path.join(cert_dir, "key.pem")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", keyfile, "-out", certfile,
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
    ], check=True, capture_output=True)
    return certfile, keyfile

# ── OAuth flow ────────────────────────────────────────────────────────────────

auth_code_result = {}

class CallbackHandler(BaseHTTPRequestHandler):
    """Tiny local server that catches the OAuth redirect."""
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        auth_code_result["code"]  = params.get("code",  [None])[0]
        auth_code_result["state"] = params.get("state", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h2>Authenticated! You can close this tab.</h2>")

    def log_message(self, *args):
        pass  # suppress server logs


def get_token_via_browser():
    """Open browser for MyChart login, capture token."""
    # 1. Discover OAuth endpoints via FHIR metadata / SMART configuration
    auth_endpoint  = None
    token_endpoint = None

    # Try SMART well-known configuration (most reliable for Epic)
    try:
        smart = requests.get(f"{FHIR_BASE}/.well-known/smart-configuration", timeout=10)
        if smart.ok:
            meta = smart.json()
            auth_endpoint  = meta.get("authorization_endpoint")
            token_endpoint = meta.get("token_endpoint")
    except requests.RequestException:
        pass

    # Try OIDC discovery
    if not auth_endpoint:
        try:
            disco = requests.get(f"{FHIR_BASE}/.well-known/openid-configuration", timeout=10)
            if disco.ok:
                meta = disco.json()
                auth_endpoint  = meta.get("authorization_endpoint")
                token_endpoint = meta.get("token_endpoint")
        except requests.RequestException:
            pass

    # Try FHIR capability statement (metadata endpoint, required by spec)
    if not auth_endpoint:
        try:
            cap = requests.get(f"{FHIR_BASE}/metadata", headers={"Accept": "application/fhir+json"}, timeout=10)
            if cap.ok:
                for rest in cap.json().get("rest", []):
                    security = rest.get("security", {})
                    for ext in security.get("extension", []):
                        if ext.get("url") == "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris":
                            for sub in ext.get("extension", []):
                                if sub.get("url") == "authorize":
                                    auth_endpoint = sub.get("valueUri")
                                elif sub.get("url") == "token":
                                    token_endpoint = sub.get("valueUri")
        except requests.RequestException:
            pass

    # Fallback to well-known Epic endpoint pattern
    if not auth_endpoint:
        oauth_base     = FHIR_BASE.replace("/api/FHIR/R4", "")
        auth_endpoint  = f"{oauth_base}/oauth2/authorize"
        token_endpoint = f"{oauth_base}/oauth2/token"
        print(f"⚠️  Could not auto-discover OAuth endpoints, using fallback: {auth_endpoint}")

    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    params = {
        "response_type":         "code",
        "client_id":             CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "scope":                 SCOPES,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "aud":                   FHIR_BASE,
    }

    url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
    print("\n🌐  Opening MyChart login in your browser...")
    webbrowser.open(url)

    # 2. Wait for redirect (HTTPS with self-signed cert for localhost)
    server = HTTPServer(("localhost", 3000), CallbackHandler)
    certfile, keyfile = _generate_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.timeout = 120
    print("⏳  Waiting for MyChart login (2-minute timeout)...")
    server.handle_request()

    code = auth_code_result.get("code")
    if not code:
        raise RuntimeError("No authorization code received. Login may have failed or timed out.")

    # 3. Exchange code for token
    token_resp = requests.post(token_endpoint, data={
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  REDIRECT_URI,
        "client_id":     CLIENT_ID,
        "code_verifier": verifier,
    }, timeout=15)
    token_resp.raise_for_status()
    token_data = token_resp.json()
    token_data["token_endpoint"]   = token_endpoint
    token_data["obtained_at"]      = time.time()
    save_token(token_data)
    return token_data


def save_token(token_data):
    TOKEN_FILE.write_text(json.dumps(token_data, indent=2))
    TOKEN_FILE.chmod(0o600)
    print(f"💾  Token saved to {TOKEN_FILE}")


def load_token():
    if TOKEN_FILE.exists():
        return json.loads(TOKEN_FILE.read_text())
    return None


def refresh_token(token_data):
    refresh = token_data.get("refresh_token")
    if not refresh:
        return None
    resp = requests.post(token_data["token_endpoint"], data={
        "grant_type":    "refresh_token",
        "refresh_token": refresh,
        "client_id":     CLIENT_ID,
    }, timeout=15)
    if resp.ok:
        new_token = resp.json()
        new_token["token_endpoint"] = token_data["token_endpoint"]
        new_token["obtained_at"]    = time.time()
        save_token(new_token)
        print("🔄  Token refreshed.")
        return new_token
    return None


def get_valid_token():
    token = load_token()
    if token:
        expires_in  = token.get("expires_in", 3600)
        obtained_at = token.get("obtained_at", 0)
        if time.time() - obtained_at < expires_in - 60:
            print("✅  Using cached token.")
            return token
        print("🔁  Token expired, attempting refresh...")
        refreshed = refresh_token(token)
        if refreshed:
            return refreshed
    print("🔐  No valid token found — starting fresh login.")
    return get_token_via_browser()


# ── FHIR helpers ──────────────────────────────────────────────────────────────

def fhir_get(path, token, params=None):
    """GET a FHIR endpoint, following pagination automatically."""
    headers = {
        "Authorization": f"Bearer {token['access_token']}",
        "Accept":        "application/fhir+json",
    }
    url = f"{FHIR_BASE}/{path}"
    results = []
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        bundle = resp.json()
        for entry in bundle.get("entry", []):
            results.append(entry.get("resource", {}))
        # Follow next page if present
        url = None
        params = None  # only on first request
        for link in bundle.get("link", []):
            if link.get("relation") == "next":
                url = link["url"]
                break
    return results


def get_patient_id(token):
    patient_id = token.get("patient")
    if patient_id:
        return patient_id
    # Fallback: fetch from /Patient
    patients = fhir_get("Patient", token)
    if patients:
        return patients[0]["id"]
    raise RuntimeError("Could not determine patient ID from token.")


# ── Download logic ────────────────────────────────────────────────────────────

def sanitize_filename(name):
    return "".join(c if c.isalnum() or c in " ._-()" else "_" for c in name).strip()


def save_document_reference(doc, token, out_dir):
    """Download and save a DocumentReference resource."""
    headers = {"Authorization": f"Bearer {token['access_token']}"}

    doc_id   = doc.get("id", "unknown")
    doc_date = doc.get("date", doc.get("context", {}).get("period", {}).get("start", "no-date"))[:10]
    doc_type = doc.get("type", {}).get("text") or \
               (doc.get("type", {}).get("coding") or [{}])[0].get("display", "Document")

    folder = out_dir / "documents"
    folder.mkdir(parents=True, exist_ok=True)
    filename_base = sanitize_filename(f"{doc_date}_{doc_type}_{doc_id}")

    for content in doc.get("content", []):
        attachment = content.get("attachment", {})
        content_type = attachment.get("contentType", "application/octet-stream")
        ext = ".pdf" if "pdf" in content_type else \
              ".html" if "html" in content_type else \
              ".txt"  if "text" in content_type else ".bin"
        filepath = folder / f"{filename_base}{ext}"

        if filepath.exists():
            return False  # already downloaded

        if "data" in attachment:
            # Inline base64
            data = base64.b64decode(attachment["data"])
            filepath.write_bytes(data)
        elif "url" in attachment:
            r = requests.get(attachment["url"], headers=headers, timeout=30)
            r.raise_for_status()
            filepath.write_bytes(r.content)
        else:
            # Save raw JSON as fallback
            filepath = folder / f"{filename_base}.json"
            filepath.write_text(json.dumps(doc, indent=2))

        print(f"  📄  Saved: {filepath.name}")
        return True

    return False


def save_diagnostic_report(report, token, out_dir):
    """Save a DiagnosticReport as JSON (contains structured lab data)."""
    folder = out_dir / "lab_results"
    folder.mkdir(parents=True, exist_ok=True)

    report_id   = report.get("id", "unknown")
    report_date = (report.get("effectiveDateTime") or report.get("issued") or "no-date")[:10]
    report_name = report.get("code", {}).get("text") or \
                  (report.get("code", {}).get("coding") or [{}])[0].get("display", "Report")

    filepath = folder / sanitize_filename(f"{report_date}_{report_name}_{report_id}.json")
    if filepath.exists():
        return False

    filepath.write_text(json.dumps(report, indent=2))
    print(f"  🧪  Saved: {filepath.name}")
    return True


def save_medication_request(med, out_dir):
    """Save a MedicationRequest as JSON."""
    folder = out_dir / "medications"
    folder.mkdir(parents=True, exist_ok=True)

    med_id   = med.get("id", "unknown")
    med_name = med.get("medicationCodeableConcept", {}).get("text") or \
               (med.get("medicationCodeableConcept", {}).get("coding") or [{}])[0].get("display", "Medication")
    authored = (med.get("authoredOn") or "no-date")[:10]

    filepath = folder / sanitize_filename(f"{authored}_{med_name}_{med_id}.json")
    if filepath.exists():
        return False

    filepath.write_text(json.dumps(med, indent=2))
    print(f"  💊  Saved: {filepath.name}")
    return True


# ── Main sync ─────────────────────────────────────────────────────────────────

def sync(token):
    patient_id = get_patient_id(token)
    print(f"\n👤  Patient ID: {patient_id}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    new_files = 0

    # 1. Clinical documents, notes, After Visit Summaries, Letters
    print("\n📂  Fetching clinical documents...")
    docs = fhir_get("DocumentReference", token, params={"patient": patient_id, "_count": 100})
    print(f"    Found {len(docs)} documents")
    for doc in docs:
        if save_document_reference(doc, token, OUTPUT_DIR):
            new_files += 1

    # 2. Lab / diagnostic reports
    print("\n🧪  Fetching diagnostic reports...")
    reports = fhir_get("DiagnosticReport", token, params={"patient": patient_id, "_count": 100})
    print(f"    Found {len(reports)} reports")
    for report in reports:
        if save_diagnostic_report(report, token, OUTPUT_DIR):
            new_files += 1

    # 3. Medications
    print("\n💊  Fetching medications...")
    meds = fhir_get("MedicationRequest", token, params={"patient": patient_id, "_count": 100})
    print(f"    Found {len(meds)} medications")
    for med in meds:
        if save_medication_request(med, OUTPUT_DIR):
            new_files += 1

    # 4. Save a summary manifest
    manifest = {
        "last_sync":   datetime.now().isoformat(),
        "patient_id":  patient_id,
        "documents":   len(docs),
        "lab_reports": len(reports),
        "medications": len(meds),
        "new_files":   new_files,
    }
    (OUTPUT_DIR / "sync_manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"\n✅  Sync complete — {new_files} new file(s) saved to {OUTPUT_DIR}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global FHIR_BASE, CLIENT_ID

    parser = argparse.ArgumentParser(description="MSK MyChart FHIR Document Sync")
    parser.add_argument("--sandbox", action="store_true",
                        help="Use Epic's sandbox environment instead of MSK production")
    args = parser.parse_args()

    if args.sandbox:
        FHIR_BASE = FHIR_BASE_SANDBOX
        CLIENT_ID = CLIENT_ID_SANDBOX
        print("🏥  MSK MyChart Sync (SANDBOX)")
    else:
        print("🏥  MSK MyChart Sync")
    print(f"    FHIR endpoint: {FHIR_BASE}")
    print("=" * 40)
    token = get_valid_token()
    sync(token)


if __name__ == "__main__":
    main()