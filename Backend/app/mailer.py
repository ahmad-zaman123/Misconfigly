import smtplib
import uuid
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from html import escape

SMTP_TIMEOUT_SECONDS = 10
# Mail clients drop web fonts and stylesheets, so everything is inline with system fonts.
FONT = "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"


def render_html(heading, text, action_label, action_url, note):
    """One email with a single button, laid out in tables so it holds up in every mail client."""
    heading, text, note = escape(heading), escape(text), escape(note)
    label, url = escape(action_label), escape(action_url, quote=True)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{heading}</title></head>
<body style="margin:0; padding:0; background-color:#f3f4f1;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f3f4f1;">
<tr><td align="center" style="padding:40px 16px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;">
    <tr><td style="padding:0 4px 20px; font-family:{FONT}; font-size:17px; font-weight:700; color:#14181f;">Misconfigly</td></tr>
    <tr><td style="background-color:#ffffff; border:1px solid #d5d8d0; border-radius:10px; padding:32px;">
      <h1 style="margin:0 0 12px; font-family:{FONT}; font-size:21px; line-height:1.3; color:#14181f;">{heading}</h1>
      <p style="margin:0 0 24px; font-family:{FONT}; font-size:15px; line-height:1.6; color:#475061; overflow-wrap:anywhere;">{text}</p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="background-color:#0f6b5c; border-radius:7px;">
        <a href="{url}" target="_blank" style="display:inline-block; padding:12px 22px; font-family:{FONT}; font-size:15px; font-weight:600; color:#ffffff; text-decoration:none;">{label}</a>
      </td></tr></table>
      <p style="margin:24px 0 0; padding-top:16px; border-top:1px solid #e4e6e0; font-family:{FONT}; font-size:13px; line-height:1.6; color:#475061;">{note}</p>
    </td></tr>
    <tr><td align="center" style="padding:18px 4px 0; font-family:{FONT}; font-size:12px; color:#6b7280;">This is an automated message, so replies aren&rsquo;t read.</td></tr>
  </table>
</td></tr>
</table>
</body>
</html>
"""


def smtp_sender(host, port, user, password, sender):
    """A function that sends one email with a single call-to-action link."""
    name, address = parseaddr(sender)
    from_header = formataddr((name or "Misconfigly", address))

    def send(to, subject, heading, text, action_label, action_url, note):
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = from_header
        message["To"] = to
        # A unique value stops Gmail grouping repeat emails and hiding the button as quoted text.
        message["X-Entity-Ref-ID"] = str(uuid.uuid4())
        message.set_content(f"{heading}\n\n{text}\n\n{action_label}: {action_url}\n\n{note}\n")
        message.add_alternative(render_html(heading, text, action_label, action_url, note), subtype="html")
        with smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(message)

    return send
