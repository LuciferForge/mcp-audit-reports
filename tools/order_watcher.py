#!/usr/bin/env python3
"""
order_watcher.py — Auto-audit daemon.

Polls Telegram for /order messages, runs audit, delivers PDF.
Runs as a daemon alongside other kingdom processes.

Flow:
  1. Customer pays $29 → submit form → /order message sent to Telegram
  2. This daemon picks it up → runs mcp-security-audit → generates PDF
  3. Sends PDF to Telegram + logs order
  4. You forward to customer from ProtonMail (or auto-email if Resend configured)
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
TOOLS = ROOT / "tools"
OUTPUT = ROOT / "output"

# Token + chat ID from environment ONLY. Never hardcode here — this file is
# in a public repo. Set via launchd EnvironmentVariables or shell rc.
TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_CHAT  = os.environ.get("TELEGRAM_CHAT_ID", "")
if not TG_TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN env var required (do not hardcode tokens here — public repo)")
POLL_INTERVAL = 30  # seconds
OFFSET_FILE = ROOT / "tools" / ".order_watcher_offset"

def tg_send(msg):
    payload = json.dumps({"chat_id": TG_CHAT, "text": msg, "parse_mode": "Markdown"}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
        data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[WARN] Telegram send failed: {e}")

def tg_send_file(path, caption):
    cmd = [
        "curl", "-s", "-X", "POST",
        f"https://api.telegram.org/bot{TG_TOKEN}/sendDocument",
        "-F", f"chat_id={TG_CHAT}",
        "-F", f"document=@{path}",
        "-F", f"caption={caption}"
    ]
    subprocess.run(cmd, capture_output=True)

def get_updates(offset):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/getUpdates?offset={offset}&timeout=20"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.loads(r.read())
            return data.get("result", [])
    except Exception as e:
        print(f"[WARN] getUpdates failed: {e}")
        return []

def load_offset():
    if OFFSET_FILE.exists():
        return int(OFFSET_FILE.read_text().strip())
    return 0

def save_offset(offset):
    OFFSET_FILE.write_text(str(offset))

def parse_order(text):
    """Parse /order message into dict."""
    order = {}
    for line in text.strip().split('\n'):
        line = line.strip()
        if line.startswith('/order'):
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            order[key.strip().lower()] = val.strip()
    return order

def run_audit(order):
    """Run full audit pipeline for an order."""
    email = order.get('email', '')
    name = order.get('name', 'Customer')
    repo = order.get('repo', '')
    company = order.get('company', '')
    server_cmd = order.get('command', '')

    if not repo:
        tg_send("⚠️ Order received but no repo URL. Check Web3Forms email.")
        return

    # Generate report ID
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    slug = re.sub(r'[^a-z0-9]', '', repo.split('/')[-1].lower())[:12].upper()
    report_id = f"LF-{today}-{slug}"
    pdf_path = str(OUTPUT / f"{report_id}.pdf")

    tg_send(
        f"🔔 *Auto-Audit Starting*\n"
        f"Report: `{report_id}`\n"
        f"Customer: {name} ({company or 'personal'})\n"
        f"Email: {email}\n"
        f"Repo: {repo}\n"
        f"Status: Scanning..."
    )

    # Step 1: Run mcp-security-audit
    scan_json_path = str(OUTPUT / f"{report_id}_scan.json")
    scan_cmd = [
        "python3", "-m", "mcp_security_audit.cli", "scan-json",
        "--server", server_cmd if server_cmd and server_cmd != 'auto' else f"npx -y {repo.split('/')[-1]}",
        "--output", scan_json_path
    ]

    # Try auto-detect server command from repo
    if not server_cmd or server_cmd == 'auto':
        # Try npx with package name from repo
        pkg_name = repo.rstrip('/').split('/')[-1]
        scan_cmd = [
            "python3", "-m", "mcp_security_audit.cli", "scan-json",
            "--server", f"npx -y {pkg_name}",
            "--output", scan_json_path
        ]

    print(f"[AUDIT] Running: {' '.join(scan_cmd)}")
    scan_result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=120)

    scan_ok = os.path.exists(scan_json_path) and os.path.getsize(scan_json_path) > 10

    if not scan_ok:
        # Try pip install approach
        scan_cmd = [
            "python3", "-m", "mcp_security_audit.cli", "scan-json",
            "--server", f"python3 -m {pkg_name.replace('-', '_')}",
            "--output", scan_json_path
        ]
        scan_result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=120)
        scan_ok = os.path.exists(scan_json_path) and os.path.getsize(scan_json_path) > 10

    if not scan_ok:
        tg_send(
            f"⚠️ *Auto-scan failed* for `{report_id}`\n"
            f"Repo: {repo}\n"
            f"Error: {scan_result.stderr[:200] if scan_result else 'unknown'}\n\n"
            f"Run manually:\n`python3 tools/process_order.py --email {email} --name \"{name}\" --repo {repo}`"
        )
        return

    # Step 2: Generate PDF
    server_name = repo.rstrip('/').split('/')[-1]
    pdf_cmd = [
        "python3", str(TOOLS / "run_audit.py"),
        "--server-name", server_name,
        "--server-repo", repo,
        "--client-name", company or name,
        "--report-id", report_id,
        "--pre-run-json", scan_json_path,
        "--output", pdf_path,
    ]

    print(f"[AUDIT] Generating PDF: {report_id}")
    pdf_result = subprocess.run(pdf_cmd, capture_output=True, text=True, timeout=60)

    if pdf_result.returncode != 0 or not os.path.exists(pdf_path):
        tg_send(
            f"⚠️ *PDF generation failed* for `{report_id}`\n"
            f"Error: {pdf_result.stderr[:200]}\n\n"
            f"Scan JSON saved at: `{scan_json_path}`\n"
            f"Run manually: `python3 tools/run_audit.py --pre-run-json {scan_json_path} --output {pdf_path}`"
        )
        return

    # Step 3: Send PDF to Telegram
    tg_send_file(pdf_path, f"📄 {report_id} — Ready to send to {email}")

    tg_send(
        f"✅ *Audit Complete*\n"
        f"Report: `{report_id}`\n"
        f"Customer: {name} <{email}>\n"
        f"Score: check PDF above\n\n"
        f"Forward the PDF above to {email} from ProtonMail."
    )

    # Step 4: Log order
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "report_id": report_id,
        "name": name,
        "email": email,
        "company": company,
        "repo": repo,
        "pdf_path": pdf_path,
        "auto": True,
    }
    orders_log = OUTPUT / "orders.jsonl"
    with open(orders_log, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

    # Step 5: Auto-email if Resend key available
    resend_key = os.environ.get("RESEND_API_KEY", "")
    if resend_key:
        email_cmd = [
            "python3", str(TOOLS / "process_order.py"),
            "--email", email,
            "--name", name,
            "--repo", repo,
            "--company", company or "",
            "--report-id", report_id,
            "--pre-run-json", scan_json_path,
            "--resend-key", resend_key,
        ]
        subprocess.run(email_cmd, capture_output=True, text=True, timeout=60)

    print(f"[AUDIT] Order complete: {report_id}")


def main():
    print(f"[WATCHER] Order watcher started. Polling every {POLL_INTERVAL}s.")
    tg_send("🤖 *Order Watcher Online*\nAuto-audit daemon is running.")

    offset = load_offset()

    while True:
        updates = get_updates(offset)
        for update in updates:
            offset = update["update_id"] + 1
            save_offset(offset)

            msg = update.get("message", {})
            text = msg.get("text", "")
            chat_id = str(msg.get("chat", {}).get("id", ""))

            # Only process /order from our chat
            if chat_id != TG_CHAT:
                continue
            if not text.startswith("/order"):
                continue

            print(f"[WATCHER] New order received")
            order = parse_order(text)

            if not order.get('repo') and not order.get('email'):
                tg_send("⚠️ Got /order but couldn't parse details. Check Web3Forms email.")
                continue

            try:
                run_audit(order)
            except Exception as e:
                tg_send(f"❌ *Auto-audit crashed*: {str(e)[:200]}\nCheck logs at /tmp/order_watcher.log")
                import traceback
                traceback.print_exc()

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
