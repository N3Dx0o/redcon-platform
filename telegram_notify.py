"""
Telegram Notification System for REDCON OFFENCE
"""
import os
import requests
from datetime import datetime

TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

def send_telegram_message(message: str, chat_id: str = None) -> bool:
    """Send a message via Telegram bot."""
    if not TELEGRAM_BOT_TOKEN:
        print("[TELEGRAM] Bot token not configured")
        return False
    
    target_chat = chat_id or TELEGRAM_CHAT_ID
    if not target_chat:
        print("[TELEGRAM] Chat ID not configured")
        return False
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    payload = {
        "chat_id": target_chat,
        "text": message,
        "parse_mode": "HTML"
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print(f"[TELEGRAM] Message sent successfully")
            return True
        else:
            print(f"[TELEGRAM] Failed: {response.text}")
            return False
    except Exception as e:
        print(f"[TELEGRAM] Error: {e}")
        return False


def notify_new_scan(project_name: str, target: str, user: str):
    """Notify when a new scan is started."""
    message = f"""
🦅 <b>REDCON HAWK - New Scan Started</b>

📁 <b>Project:</b> {project_name}
🎯 <b>Target:</b> {target}
👤 <b>User:</b> {user}
🕐 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Scan in progress...
"""
    return send_telegram_message(message)


def notify_scan_complete(project_name: str, target: str, findings_count: int, critical: int = 0, high: int = 0):
    """Notify when a scan is complete."""
    severity_emoji = "🔴" if critical > 0 else "🟠" if high > 0 else "🟢"
    
    message = f"""
{severity_emoji} <b>REDCON HAWK - Scan Complete</b>

📁 <b>Project:</b> {project_name}
🎯 <b>Target:</b> {target}
🕐 <b>Completed:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 <b>Results:</b>
• Total Findings: {findings_count}
• Critical: {critical}
• High: {high}

View full report in the dashboard.
"""
    return send_telegram_message(message)


def notify_new_finding(pentest_name: str, finding_title: str, severity: str, pentester: str):
    """Notify when a new finding is submitted."""
    severity_emojis = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': '⚪'
    }
    emoji = severity_emojis.get(severity.lower(), '⚪')
    
    message = f"""
{emoji} <b>REDCON BLACKOPS - New Finding</b>

🎯 <b>Pentest:</b> {pentest_name}
📋 <b>Finding:</b> {finding_title}
⚠️ <b>Severity:</b> {severity.upper()}
👤 <b>Submitted by:</b> {pentester}
🕐 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    return send_telegram_message(message)


def notify_pentest_started(pentest_name: str, client: str, pentesters: list):
    """Notify when a pentest begins."""
    pentesters_str = ", ".join(pentesters) if pentesters else "TBD"
    
    message = f"""
🎖️ <b>REDCON BLACKOPS - Pentest Started</b>

📁 <b>Project:</b> {pentest_name}
🏢 <b>Client:</b> {client}
👥 <b>Team:</b> {pentesters_str}
🕐 <b>Started:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Operation is now ACTIVE.
"""
    return send_telegram_message(message)


def notify_pentest_complete(pentest_name: str, client: str, total_findings: int):
    """Notify when a pentest is complete."""
    message = f"""
✅ <b>REDCON BLACKOPS - Pentest Complete</b>

📁 <b>Project:</b> {pentest_name}
🏢 <b>Client:</b> {client}
📊 <b>Total Findings:</b> {total_findings}
🕐 <b>Completed:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Report ready for review.
"""
    return send_telegram_message(message)


def notify_demo_request(name: str, email: str, company: str, interest: str):
    """Notify when someone requests a demo."""
    message = f"""
🎯 <b>REDCON - New Demo Request</b>

👤 <b>Name:</b> {name}
📧 <b>Email:</b> {email}
🏢 <b>Company:</b> {company}
💼 <b>Interest:</b> {interest}
🕐 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Follow up ASAP!
"""
    return send_telegram_message(message)


def notify_new_signup(name: str, email: str, role: str):
    """Notify when a new user signs up."""
    message = f"""
👤 <b>REDCON - New User Signup</b>

👤 <b>Name:</b> {name}
📧 <b>Email:</b> {email}
🎭 <b>Role:</b> {role}
🕐 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    return send_telegram_message(message)


# Test function
if __name__ == "__main__":
    print("Testing Telegram notifications...")
    result = send_telegram_message("🎖️ <b>REDCON OFFENCE</b>\n\nTelegram notifications are now active!")
    print(f"Test result: {'Success' if result else 'Failed'}")

