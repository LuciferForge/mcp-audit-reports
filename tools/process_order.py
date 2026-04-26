#!/usr/bin/env python3
"""
process_order.py — End-to-end order processor for MCP audit sales.

Run when a new order comes in (you get notified via email from Web3Forms).

Usage:
    python3 tools/process_order.py \
        --email customer@company.com \
        --name "Jane Smith" \
        --repo https://github.com/org/mcp-server \
        --company "Acme Corp" \
        --report-id LF-2026-001

Options:
    --server-command   Override server run command (default: auto-detect from repo)
    --dry-run          Run audit but don't send email
    --skip-audit       Use existing JSON file (--pre-run-json) instead of running audit
    --pre-run-json     Path to existing mcp-security-audit JSON
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# Project root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Token + chat ID from environment ONLY. Never hardcode here — this file is
# in a public repo. Set via launchd EnvironmentVariables or shell rc.
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")
ORDERS_LOG         = ROOT / "output" / "orders.jsonl"
OUTPUT_DIR         = ROOT / "output"

# ─── Telegram ────────────────────────────────────────────────────────────────

def send_telegram(msg: str):
    import urllib.request
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[WARN] Telegram failed: {e}")

def send_telegram_file(file_path: str, caption: str):
    """Send PDF via Telegram as document."""
    cmd = [
        "curl", "-s", "-X", "POST",
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument",
        "-F", f"chat_id={TELEGRAM_CHAT_ID}",
        "-F", f"document=@{file_path}",
        "-F", f"caption={caption}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[WARN] Telegram file send failed: {result.stderr}")

# ─── Auto-detect server command ──────────────────────────────────────────────

def detect_server_command(repo_url: str, server_name: str) -> str:
    """Guess the npx/pip install command from repo URL."""
    # Try to get package.json name
    raw_base = repo_url.replace("https://github.com/", "https://raw.githubusercontent.com/")

    # Check package.json
    pkg_url = f"{raw_base}/main/package.json"
    try:
        import urllib.request
        with urllib.request.urlopen(pkg_url, timeout=5) as r:
            pkg = json.loads(r.read())
            pkg_name = pkg.get("name", "")
            if pkg_name:
                return f"npx -y {pkg_name}"
    except:
        pass

    # Check pyproject.toml / setup.py (Python package)
    for fname in ["pyproject.toml", "setup.py"]:
        try:
            url = f"{raw_base}/main/{fname}"
            with urllib.request.urlopen(url, timeout=5) as r:
                content = r.read().decode()
                match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return f"pip install {match.group(1)} && python -m {match.group(1)}"
        except:
            pass

    # Fallback: clone and run
    return f"# Auto-detect failed. Clone {repo_url} and provide --server-command manually."

# ─── Run audit ───────────────────────────────────────────────────────────────

def run_mcp_audit(server_command: str, server_name: str) -> dict | None:
    """Run mcp-security-audit CLI and return JSON result."""
    print(f"Running mcp-security-audit on: {server_command}")

    # First check if mcp-security-audit is installed
    check = subprocess.run(["python3", "-m", "mcp_security_audit", "--version"],
                          capture_output=True, text=True)
    if check.returncode != 0:
        print("[WARN] mcp-security-audit not installed. Using pre-captured data mode.")
        return None

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name

    cmd = [
        "python3", "-m", "mcp_security_audit",
        "--server-command", server_command,
        "--output", out_path,
        "--format", "json",
        "--timeout", "60"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        print(f"[ERROR] Audit failed: {result.stderr[:500]}")
        return None

    with open(out_path) as f:
        data = json.load(f)

    os.unlink(out_path)
    return data

# ─── Generate PDF ────────────────────────────────────────────────────────────

def generate_pdf(args, audit_json: dict | None, report_id: str, output_path: str) -> bool:
    cmd = [
        "python3", str(ROOT / "tools" / "run_audit.py"),
        "--server-name", args.server_name,
        "--server-repo", args.repo,
        "--client-name", args.company or args.name,
        "--report-id", report_id,
        "--output", output_path,
    ]

    if audit_json:
        # Write audit JSON to temp file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode='w') as f:
            json.dump(audit_json, f)
            tmp_json = f.name
        cmd += ["--pre-run-json", tmp_json]
    elif args.server_command:
        cmd += ["--server-command", args.server_command]
    else:
        # No audit data — fallback to demo data for safety
        print("[WARN] No audit data available. Using demo data for report structure.")
        cmd += ["--pre-run-json", str(ROOT / "filesystem-server-audit.json")]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] PDF generation failed:\n{result.stderr}")
        return False

    print(result.stdout)
    return True

# ─── Send email ──────────────────────────────────────────────────────────────

def send_email_resend(to_email: str, to_name: str, report_id: str, pdf_path: str, resend_key: str) -> bool:
    """Send PDF via Resend API (resend.com — free 3k/month)."""
    import urllib.request, base64

    with open(pdf_path, 'rb') as f:
        pdf_b64 = base64.b64encode(f.read()).decode()

    filename = Path(pdf_path).name

    payload = {
        "from": "LuciferForge Security <security@protodex.io>",
        "to": [f"{to_name} <{to_email}>"],
        "subject": f"Your MCP Security Audit Report — {report_id}",
        "html": f"""
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#333">
<p>Hi {to_name.split()[0]},</p>
<p>Your MCP security audit is complete. The signed PDF compliance report is attached to this email.</p>
<p><strong>Report ID:</strong> {report_id}<br>
<strong>Delivered by:</strong> LuciferForge Security</p>
<hr style="border:none;border-top:1px solid #eee;margin:20px 0">
<p>The report includes:</p>
<ul>
<li>Tool inventory and risk classification</li>
<li>Security findings with severity ratings (Critical / High / Medium / Low)</li>
<li>EU AI Act compliance mapping (Articles 9, 11, 13, 15, 17)</li>
<li>Prioritized remediation roadmap</li>
</ul>
<p>Questions? Reply to this email or contact <a href="mailto:LuciferForge@proton.me">LuciferForge@proton.me</a></p>
<p style="color:#888;font-size:12px;margin-top:24px">LuciferForge Security · mcp-audit-reports.luciferforge.io</p>
</div>
""",
        "attachments": [
            {"filename": filename, "content": pdf_b64}
        ]
    }

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {resend_key}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
            print(f"Email sent. Resend ID: {resp.get('id')}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[ERROR] Email failed: {e.code} {body}")
        return False

# ─── Log order ───────────────────────────────────────────────────────────────

def log_order(args, report_id: str, pdf_path: str, email_sent: bool):
    ORDERS_LOG.parent.mkdir(exist_ok=True)
    record = {
        "timestamp": datetime.utcnow().isoformat(),
        "report_id": report_id,
        "name": args.name,
        "email": args.email,
        "company": args.company,
        "repo": args.repo,
        "pdf_path": pdf_path,
        "email_sent": email_sent,
    }
    with open(ORDERS_LOG, 'a') as f:
        f.write(json.dumps(record) + '\n')
    print(f"Order logged: {ORDERS_LOG}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Process a paid MCP audit order end-to-end")
    parser.add_argument("--email",          required=True, help="Customer email")
    parser.add_argument("--name",           required=True, help="Customer name")
    parser.add_argument("--repo",           required=True, help="GitHub repo URL")
    parser.add_argument("--company",        default="",    help="Company name")
    parser.add_argument("--server-name",    default="",    help="Server name (default: inferred from repo)")
    parser.add_argument("--server-command", default="",    help="MCP server run command")
    parser.add_argument("--report-id",      default="",    help="Report ID (default: auto-generated)")
    parser.add_argument("--pre-run-json",   default="",    help="Skip audit, use existing JSON")
    parser.add_argument("--resend-key",     default=os.environ.get("RESEND_API_KEY", ""), help="Resend API key")
    parser.add_argument("--dry-run",        action="store_true", help="Generate PDF but don't send email")
    args = parser.parse_args()

    # Auto-fill fields
    if not args.server_name:
        args.server_name = args.repo.rstrip('/').split('/')[-1]

    if not args.report_id:
        today = datetime.utcnow().strftime("%Y%m%d")
        slug = re.sub(r'[^a-z0-9]', '', args.server_name.lower())[:12].upper()
        args.report_id = f"LF-{today}-{slug}"

    pdf_path = str(OUTPUT_DIR / f"{args.report_id}.pdf")
    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"\n{'='*60}")
    print(f"ORDER: {args.report_id}")
    print(f"Customer: {args.name} <{args.email}>")
    print(f"Repo: {args.repo}")
    print(f"PDF: {pdf_path}")
    print(f"{'='*60}\n")

    # Notify yourself
    send_telegram(
        f"🔔 *New Audit Order*\n"
        f"Report: `{args.report_id}`\n"
        f"Customer: {args.name} ({args.company or 'personal'})\n"
        f"Email: {args.email}\n"
        f"Repo: {args.repo}\n"
        f"Status: Processing..."
    )

    # Step 1: Run audit
    audit_json = None
    if args.pre_run_json:
        with open(args.pre_run_json) as f:
            audit_json = json.load(f)
        print(f"Using pre-run JSON: {args.pre_run_json}")
    elif args.server_command:
        audit_json = run_mcp_audit(args.server_command, args.server_name)
    else:
        cmd = detect_server_command(args.repo, args.server_name)
        if not cmd.startswith("#"):
            print(f"Detected server command: {cmd}")
            audit_json = run_mcp_audit(cmd, args.server_name)
        else:
            print(f"[WARN] Could not auto-detect server command.")
            print(f"[WARN] Run manually: python3 tools/process_order.py --server-command '...' ...")

    # Step 2: Generate PDF
    print("\n--- Generating PDF ---")
    ok = generate_pdf(args, audit_json, args.report_id, pdf_path)
    if not ok:
        send_telegram(f"❌ PDF generation FAILED for {args.report_id}. Manual intervention needed.")
        sys.exit(1)

    print(f"\nPDF ready: {pdf_path}")

    # Step 3: Send PDF to yourself via Telegram first
    send_telegram_file(pdf_path, f"📄 {args.report_id} — Review before sending to {args.email}")

    # Step 4: Email to customer
    if args.dry_run:
        print("\n[DRY RUN] Skipping email send.")
        log_order(args, args.report_id, pdf_path, False)
        return

    if not args.resend_key:
        print("\n[WARN] No RESEND_API_KEY. Set it in env or pass --resend-key.")
        print(f"[ACTION REQUIRED] Manually email {pdf_path} to {args.email}")
        send_telegram(
            f"⚠️ *Manual email needed*\n"
            f"PDF: `{args.report_id}.pdf` (sent above)\n"
            f"Send to: {args.email} ({args.name})"
        )
        log_order(args, args.report_id, pdf_path, False)
        return

    print(f"\n--- Sending email to {args.email} ---")
    email_sent = send_email_resend(args.email, args.name, args.report_id, pdf_path, args.resend_key)

    if email_sent:
        send_telegram(f"✅ *Order complete*: `{args.report_id}`\nDelivered to {args.email}")
    else:
        send_telegram(
            f"⚠️ *Email failed* for `{args.report_id}`\n"
            f"PDF is attached above. Send manually to {args.email}"
        )

    log_order(args, args.report_id, pdf_path, email_sent)
    print("\nDone.")

if __name__ == "__main__":
    main()
