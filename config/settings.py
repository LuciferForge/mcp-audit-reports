"""
Configuration — audit report service settings.

All secrets loaded from environment. Never hardcode.
"""

import os

# Report metadata
AUDITOR_NAME = os.getenv("AUDITOR_NAME", "LuciferForge Security")
AUDITOR_EMAIL = os.getenv("AUDITOR_EMAIL", "LuciferForge@proton.me")

# Payment
PAYPAL_EMAIL = os.getenv("PAYPAL_EMAIL", "")
STRIPE_KEY = os.getenv("STRIPE_SECRET_KEY", "")  # Future

# Report pricing (USD)
PRICE_SINGLE = 200
PRICE_MULTI = 500

# Output paths
OUTPUT_DIR = os.getenv("AUDIT_OUTPUT_DIR", "./output")
TEMPLATE_DIR = os.getenv("AUDIT_TEMPLATE_DIR", "./templates")

# Report ID format: LF-YYYY-NNN
# Increment NNN manually per report. Track in a local reports.json.
REPORTS_REGISTRY = os.getenv("REPORTS_REGISTRY", "./config/reports_registry.json")
