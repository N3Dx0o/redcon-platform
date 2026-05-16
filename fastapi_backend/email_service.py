"""
Email notification service using Google Workspace SMTP
Handles all email notifications for the REDCON platform
"""
import smtplib
import os as _os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List, Dict


# Google Workspace SMTP configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = _os.getenv("SMTP_USERNAME", "notification@redconoffence.com")
SMTP_PASSWORD = _os.getenv("SMTP_PASSWORD")
FROM_EMAIL = "notification@redconoffence.com"
FROM_NAME = "REDCON OFFENCE"


def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    category: str = "notification",
    reply_to: Optional[str] = None
) -> bool:
    """
    Send an email via Google Workspace SMTP

    Args:
        to_email: Recipient email address
        subject: Email subject
        html_body: HTML content
        text_body: Plain text fallback (optional)
        category: Email category for tracking
        reply_to: Reply-to email address

    Returns:
        True if sent successfully, False otherwise
    """
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{FROM_NAME} <{FROM_EMAIL}>"
        msg['To'] = to_email
        msg['Subject'] = subject

        if reply_to:
            msg['Reply-To'] = reply_to

        # Add X-Category header for tracking
        msg['X-Category'] = category

        # Attach text version (if provided)
        if text_body:
            part_text = MIMEText(text_body, 'plain', 'utf-8')
            msg.attach(part_text)

        # Attach HTML version
        part_html = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(part_html)

        # Send via SMTP
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)

        return True

    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send to {to_email}: {str(e)}")
        return False


def send_bulk_email(
    recipients: List[str],
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    category: str = "notification"
) -> Dict[str, bool]:
    """
    Send email to multiple recipients

    Returns:
        Dict mapping email addresses to success status
    """
    results = {}
    for email in recipients:
        if email and "@" in email:
            results[email] = send_email(email, subject, html_body, text_body, category)
    return results


# ============================================================
# EMAIL TEMPLATES
# ============================================================

def _email_wrapper(content: str) -> str:
    """Wrap email content in REDCON-branded template"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: #f4f4f4;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background: #f4f4f4; padding: 20px 0;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #e84855; font-size: 28px; font-weight: 700; letter-spacing: 1px;">REDCON</h1>
                            <p style="margin: 5px 0 0; color: rgba(255,255,255,0.7); font-size: 12px; letter-spacing: 2px; text-transform: uppercase;">Offensive Security</p>
                        </td>
                    </tr>

                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            {content}
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background: #f8f9fa; padding: 20px 30px; border-top: 1px solid #e9ecef;">
                            <p style="margin: 0; color: #6c757d; font-size: 12px; text-align: center;">
                                © 2026 REDCON OFFENCE. All rights reserved.<br>
                                <a href="https://platform.redconoffence.com" style="color: #e84855; text-decoration: none;">Visit Platform</a>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""


def email_pentest_request_to_admin(pentest_id: str, pentest_title: str, client_name: str, pentest_type: str) -> str:
    """Email to admin when client requests a new pentest"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">New Pentest Request</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            A new pentest request has been submitted and requires your review.
        </p>
        <div style="background: #f8f9fa; border-left: 4px solid #e84855; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Client:</strong> {client_name}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>Type:</strong> {pentest_type}</p>
            <p style="margin: 0; color: #555;"><strong>ID:</strong> {pentest_id}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/admin/pentests"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Review Request
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_pentest_approved(pentest_id: str, pentest_title: str, start_date: str, client_name: str) -> str:
    """Email to client when pentest is approved"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Pentest Approved! 🎉</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Great news! Your pentest request has been approved and is being scheduled.
        </p>
        <div style="background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {pentest_id}</p>
            <p style="margin: 0; color: #555;"><strong>Start Date:</strong> {start_date}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/pentests"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Details
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_pentest_rejected(pentest_title: str, reason: str, client_name: str) -> str:
    """Email to client when pentest is rejected"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Pentest Request Update</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            We've reviewed your pentest request for <strong>{pentest_title}</strong>.
        </p>
        <div style="background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 10px; color: #555;"><strong>Status:</strong> Requires clarification</p>
            <p style="margin: 0; color: #555;">{reason or 'Please contact us for more details.'}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/pentests"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Contact Support
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_pentester_assigned(pentest_id: str, pentest_title: str, pentester_name: str, start_date: str) -> str:
    """Email to pentester when assigned to a pentest"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">New Assignment</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            You've been assigned to a new pentest engagement.
        </p>
        <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {pentest_id}</p>
            <p style="margin: 0; color: #555;"><strong>Start Date:</strong> {start_date}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/ptaas/pentests"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Assignment
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_pentest_started(pentest_id: str, pentest_title: str, start_date: str) -> str:
    """Email when pentest is started"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Pentest Started 🚀</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Your security assessment has officially begun.
        </p>
        <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {pentest_id}</p>
            <p style="margin: 0; color: #555;"><strong>Started:</strong> {start_date}</p>
        </div>
        <p style="margin: 15px 0; color: #555; line-height: 1.6;">
            Our team is now actively testing your systems. You'll receive updates as findings are identified.
        </p>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/pentests"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Progress
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_pentest_finished(pentest_id: str, pentest_title: str, findings_count: int) -> str:
    """Email when pentest is completed"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Pentest Completed ✓</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Your security assessment has been completed. The final report is now available.
        </p>
        <div style="background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {pentest_id}</p>
            <p style="margin: 0; color: #555;"><strong>Findings Identified:</strong> {findings_count}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/reports"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Generate Report
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_report_generated(pentest_id: str, pentest_title: str, report_url: str) -> str:
    """Email when report PDF is generated"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Security Report Ready 📄</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Your professional security assessment report has been generated and is ready to download.
        </p>
        <div style="background: #f8f9fa; border-left: 4px solid #e84855; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
            <p style="margin: 0; color: #555;"><strong>ID:</strong> {pentest_id}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/reports"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Download Report
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_new_finding(finding_id: str, finding_title: str, severity: str, pentest_title: str) -> str:
    """Email to client when a new finding is submitted"""
    severity_colors = {
        "critical": "#dc3545",
        "high": "#e84855",
        "medium": "#f39c12",
        "low": "#3498db",
        "info": "#6c757d"
    }
    color = severity_colors.get(severity.lower(), "#6c757d")

    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">New Security Finding</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            A new security finding has been identified in <strong>{pentest_title}</strong>.
        </p>
        <div style="background: #fff3cd; border-left: 4px solid {color}; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Finding:</strong> {finding_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {finding_id}</p>
            <p style="margin: 0; color: #555;">
                <strong>Severity:</strong>
                <span style="background: {color}; color: white; padding: 3px 10px; border-radius: 3px; font-size: 11px; text-transform: uppercase; font-weight: 600;">
                    {severity}
                </span>
            </p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/findings"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Finding
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_finding_status_changed(finding_id: str, finding_title: str, old_status: str, new_status: str) -> str:
    """Email when finding status changes"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Finding Status Updated</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            The status of a security finding has been updated.
        </p>
        <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Finding:</strong> {finding_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {finding_id}</p>
            <p style="margin: 0; color: #555;"><strong>Status:</strong> {old_status} → {new_status}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/findings"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Finding
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_new_comment(finding_id: str, finding_title: str, commenter_name: str, comment_preview: str) -> str:
    """Email when someone comments on a finding"""
    preview = (comment_preview[:150] + "...") if len(comment_preview) > 150 else comment_preview

    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">New Comment on Finding</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            <strong>{commenter_name}</strong> added a comment to <strong>{finding_title}</strong>.
        </p>
        <div style="background: #f8f9fa; border-left: 4px solid #6c757d; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Finding:</strong> {finding_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {finding_id}</p>
            <p style="margin: 10px 0 0; color: #666; font-style: italic;">"{preview}"</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/findings"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Read Comment
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_client_responded(finding_id: str, finding_title: str, client_name: str) -> str:
    """Email to pentester when client responds to a finding"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Client Response on Finding</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            The client has responded to one of your findings.
        </p>
        <div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Finding:</strong> {finding_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {finding_id}</p>
            <p style="margin: 0; color: #555;"><strong>Client:</strong> {client_name}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/ptaas/findings"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Response
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_welcome_user(user_name: str, user_email: str, role: str, temp_password: Optional[str] = None) -> str:
    """Welcome email for new users"""
    role_info = {
        "client": ("Client Dashboard", "/app/client/dashboard"),
        "pentester": ("Pentester Dashboard", "/app/ptaas/pentests"),
        "admin": ("Admin Panel", "/app/admin/dashboard"),
    }
    dashboard_name, dashboard_path = role_info.get(role.lower(), ("Dashboard", "/app/portal"))

    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Welcome to REDCON Platform!</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Your account has been created successfully.
        </p>
        <div style="background: #f8f9fa; border-left: 4px solid #e84855; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Name:</strong> {user_name}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>Email:</strong> {user_email}</p>
            <p style="margin: 0; color: #555;"><strong>Role:</strong> {role.title()}</p>
        </div>
        {f'<p style="margin: 15px 0; color: #d32f2f; background: #ffebee; padding: 12px; border-radius: 6px;"><strong>Temporary Password:</strong> {temp_password}<br><small>Please change this after your first login.</small></p>' if temp_password else ''}
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com{dashboard_path}"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Access {dashboard_name}
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_finding_ready_retest(finding_id: str, finding_title: str, pentest_title: str) -> str:
    """Email to pentester when finding is marked ready for retest"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Finding Ready for Retest</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            A finding has been marked as ready for retesting.
        </p>
        <div style="background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Finding:</strong> {finding_title}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>ID:</strong> {finding_id}</p>
            <p style="margin: 0; color: #555;"><strong>Pentest:</strong> {pentest_title}</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/ptaas/findings"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Start Retest
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_password_reset(user_name: str, reset_url: str) -> str:
    """Password reset email with secure link"""
    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Password Reset Request</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            We received a request to reset your password for your REDCON OFFENCE account.
        </p>
        <p style="margin: 15px 0; color: #555; line-height: 1.6;">
            Click the button below to create a new password:
        </p>
        <table cellpadding="0" cellspacing="0" border="0" style="margin: 20px 0;">
            <tr>
                <td align="center" bgcolor="#e84855" style="border-radius: 6px;">
                    <a href="{reset_url}"
                       target="_blank"
                       style="display: inline-block; background: #e84855; color: #ffffff !important; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px; font-family: Arial, sans-serif;">
                        Reset Password
                    </a>
                </td>
            </tr>
        </table>
        <p style="margin: 15px 0; color: #666; font-size: 12px; line-height: 1.6;">
            If the button doesn't work, copy and paste this link into your browser:
        </p>
        <p style="margin: 0 0 20px; padding: 10px; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; word-break: break-all; font-family: monospace; font-size: 11px; color: #333;">
            {reset_url}
        </p>
        <div style="background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #666; font-size: 13px; line-height: 1.6;">
                <strong>Security Note:</strong> This link will expire in 1 hour and can only be used once.
                If you didn't request this reset, you can safely ignore this email.
            </p>
        </div>
    """
    return _email_wrapper(content)


def email_password_reset_confirmation() -> str:
    """Password reset confirmation email"""
    content = """
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Password Reset Successful</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Your password has been successfully reset.
        </p>
        <div style="background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #555;">
                ✓ Your password has been changed and is now active.
            </p>
        </div>
        <p style="margin: 15px 0; color: #555; line-height: 1.6;">
            You can now sign in to your account using your new password.
        </p>
        <p style="margin: 20px 0;">
            <a href="https://platform.redconoffence.com/app/portal"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                Sign In
            </a>
        </p>
        <div style="background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #666; font-size: 13px; line-height: 1.6;">
                <strong>Security Alert:</strong> If you didn't make this change, please contact us immediately at
                <a href="mailto:admin@redconoffence.com" style="color: #e84855;">admin@redconoffence.com</a>
            </p>
        </div>
    """
    return _email_wrapper(content)


def email_mention_notification(mentioned_user_name: str, finding_title: str, commenter_name: str, comment_preview: str) -> str:
    """Email when user is @mentioned in a comment"""
    preview = (comment_preview[:150] + "...") if len(comment_preview) > 150 else comment_preview

    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">You Were Mentioned</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            <strong>{commenter_name}</strong> mentioned you in a comment on <strong>{finding_title}</strong>.
        </p>
        <div style="background: #f8f9fa; border-left: 4px solid #9c27b0; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #666; font-style: italic;">"{preview}"</p>
        </div>
        <p style="margin: 20px 0 0;">
            <a href="https://platform.redconoffence.com/app/client/findings"
               style="display: inline-block; background: #e84855; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 600;">
                View Comment
            </a>
        </p>
    """
    return _email_wrapper(content)


def email_welcome_user_setup_link(user_name: str, user_email: str, role: str, setup_url: str) -> str:
    """Welcome email with secure setup link (no password)"""
    role_info = {
        "client": ("Client Dashboard", "manage your security assessments"),
        "pentester": ("Pentester Dashboard", "start working on pentests"),
        "admin": ("Admin Panel", "manage the platform"),
    }
    dashboard_name, dashboard_desc = role_info.get(role.lower(), ("Dashboard", "access the platform"))

    content = f"""
        <h2 style="margin: 0 0 20px; color: #1a1a2e; font-size: 22px;">Welcome to REDCON Platform!</h2>
        <p style="margin: 0 0 15px; color: #333; line-height: 1.6;">
            Your account has been created. Complete your setup to start using the platform.
        </p>
        <div style="background: #f8f9fa; border-left: 4px solid #e84855; padding: 15px; margin: 20px 0;">
            <p style="margin: 0 0 8px; color: #555;"><strong>Name:</strong> {user_name}</p>
            <p style="margin: 0 0 8px; color: #555;"><strong>Email:</strong> {user_email}</p>
            <p style="margin: 0; color: #555;"><strong>Role:</strong> {role.title()}</p>
        </div>
        <p style="margin: 15px 0; color: #555; line-height: 1.6;">
            Click the button below to create your password and access your {dashboard_name}:
        </p>
        <table cellpadding="0" cellspacing="0" border="0" style="margin: 20px 0;">
            <tr>
                <td align="center" bgcolor="#e84855" style="border-radius: 6px;">
                    <a href="{setup_url}"
                       target="_blank"
                       style="display: inline-block; background: #e84855; color: #ffffff !important; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px; font-family: Arial, sans-serif;">
                        Set Up Your Account
                    </a>
                </td>
            </tr>
        </table>
        <p style="margin: 15px 0; color: #666; font-size: 12px; line-height: 1.6;">
            If the button doesn't work, copy and paste this link into your browser:
        </p>
        <p style="margin: 0 0 20px; padding: 10px; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; word-break: break-all; font-family: monospace; font-size: 11px; color: #333;">
            {setup_url}
        </p>
        <p style="margin: 20px 0 0; color: #666; font-size: 13px; line-height: 1.6;">
            <strong>Security Note:</strong> This link will expire in 24 hours and can only be used once.
            Never share this link with anyone.
        </p>
    """
    return _email_wrapper(content)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def notify_pentest_requested(pentest_id: str, pentest_title: str, client_name: str, pentest_type: str, admin_emails: List[str]):
    """Notify admins of new pentest request"""
    subject = f"New Pentest Request: {pentest_title}"
    html = email_pentest_request_to_admin(pentest_id, pentest_title, client_name, pentest_type)
    return send_bulk_email(admin_emails, subject, html, category="pentest_request")


def notify_pentest_approved(client_email: str, pentest_id: str, pentest_title: str, start_date: str, client_name: str):
    """Notify client that their pentest was approved"""
    subject = f"Pentest Approved: {pentest_title}"
    html = email_pentest_approved(pentest_id, pentest_title, start_date, client_name)
    return send_email(client_email, subject, html, category="pentest_approved")


def notify_pentest_rejected(client_email: str, pentest_title: str, reason: str, client_name: str):
    """Notify client that their pentest was rejected"""
    subject = f"Pentest Request Update: {pentest_title}"
    html = email_pentest_rejected(pentest_title, reason, client_name)
    return send_email(client_email, subject, html, category="pentest_rejected")


def notify_pentester_assigned(pentester_email: str, pentest_id: str, pentest_title: str, pentester_name: str, start_date: str):
    """Notify pentester of new assignment"""
    subject = f"New Assignment: {pentest_title}"
    html = email_pentester_assigned(pentest_id, pentest_title, pentester_name, start_date)
    return send_email(pentester_email, subject, html, category="pentester_assigned")


def notify_pentest_started(emails: List[str], pentest_id: str, pentest_title: str, start_date: str):
    """Notify client and pentesters when pentest starts"""
    subject = f"Pentest Started: {pentest_title}"
    html = email_pentest_started(pentest_id, pentest_title, start_date)
    return send_bulk_email(emails, subject, html, category="pentest_started")


def notify_pentest_finished(client_email: str, pentest_id: str, pentest_title: str, findings_count: int):
    """Notify client when pentest is completed"""
    subject = f"Pentest Completed: {pentest_title}"
    html = email_pentest_finished(pentest_id, pentest_title, findings_count)
    return send_email(client_email, subject, html, category="pentest_finished")


def notify_report_generated(client_email: str, pentest_id: str, pentest_title: str, report_url: str):
    """Notify client when report is ready"""
    subject = f"Security Report Ready: {pentest_title}"
    html = email_report_generated(pentest_id, pentest_title, report_url)
    return send_email(client_email, subject, html, category="report_generated")


def notify_new_finding(client_email: str, finding_id: str, finding_title: str, severity: str, pentest_title: str):
    """Notify client of new finding"""
    subject = f"New {severity.title()} Finding: {finding_title}"
    html = email_new_finding(finding_id, finding_title, severity, pentest_title)
    return send_email(client_email, subject, html, category="new_finding")


def notify_finding_status_changed(emails: List[str], finding_id: str, finding_title: str, old_status: str, new_status: str):
    """Notify relevant users of finding status change"""
    subject = f"Finding Status Updated: {finding_title}"
    html = email_finding_status_changed(finding_id, finding_title, old_status, new_status)
    return send_bulk_email(emails, subject, html, category="finding_status")


def notify_new_comment(emails: List[str], finding_id: str, finding_title: str, commenter_name: str, comment_text: str):
    """Notify relevant users of new comment"""
    subject = f"New comment on: {finding_title}"
    html = email_new_comment(finding_id, finding_title, commenter_name, comment_text)
    return send_bulk_email(emails, subject, html, category="new_comment")


def notify_client_responded(pentester_emails: List[str], finding_id: str, finding_title: str, client_name: str):
    """Notify pentesters when client responds"""
    subject = f"Client response: {finding_title}"
    html = email_client_responded(finding_id, finding_title, client_name)
    return send_bulk_email(pentester_emails, subject, html, category="client_response")


def notify_ready_retest(pentester_emails: List[str], finding_id: str, finding_title: str, pentest_title: str):
    """Notify pentesters when finding is ready for retest"""
    subject = f"Ready for Retest: {finding_title}"
    html = email_finding_ready_retest(finding_id, finding_title, pentest_title)
    return send_bulk_email(pentester_emails, subject, html, category="retest_ready")


def notify_welcome_user(user_email: str, user_name: str, role: str, temp_password: Optional[str] = None):
    """Send welcome email to new user"""
    subject = "Welcome to REDCON Platform"
    html = email_welcome_user(user_name, user_email, role, temp_password)
    return send_email(user_email, subject, html, category="welcome")


def send_password_reset_email(user_email: str, user_name: str, reset_url: str):
    """Send password reset email"""
    subject = "Reset Your Password - REDCON OFFENCE"
    html = email_password_reset(user_name, reset_url)

    text = f"""
Reset Your Password

We received a request to reset your password for your REDCON OFFENCE account.

Reset your password by clicking this link:
{reset_url}

This link will expire in 1 hour and can only be used once.

If you didn't request this reset, you can safely ignore this email.

---
© 2026 REDCON OFFENCE. All rights reserved.
"""

    return send_email(user_email, subject, html, text_body=text, category="password_reset", reply_to="admin@redconoffence.com")


def send_password_reset_confirmation(user_email: str):
    """Send confirmation after password is reset"""
    subject = "Password Reset Successful - REDCON OFFENCE"
    html = email_password_reset_confirmation()

    text = """
Password Reset Successful

Your password has been successfully reset.

You can now sign in to your account using your new password.

Sign in: https://platform.redconoffence.com/app/portal

If you didn't make this change, please contact us immediately at admin@redconoffence.com

---
© 2026 REDCON OFFENCE. All rights reserved.
"""

    return send_email(user_email, subject, html, text_body=text, category="password_reset_confirm", reply_to="admin@redconoffence.com")


def notify_welcome_user_with_setup_link(user_email: str, user_name: str, role: str, setup_url: str):
    """Send welcome email with secure setup link (no password)"""
    subject = "Welcome to REDCON Platform - Set Up Your Account"
    html = email_welcome_user_setup_link(user_name, user_email, role, setup_url)

    # Plain text version for better deliverability
    text = f"""
Welcome to REDCON Platform!

Your account has been created. Complete your setup to start using the platform.

Name: {user_name}
Email: {user_email}
Role: {role.title()}

Set up your account by clicking this link:
{setup_url}

This link will expire in 24 hours and can only be used once.

---
© 2026 REDCON OFFENCE. All rights reserved.
https://platform.redconoffence.com
"""

    return send_email(user_email, subject, html, text_body=text, category="welcome_setup", reply_to="admin@redconoffence.com")
