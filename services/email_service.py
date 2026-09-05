"""Provider boundary for transactional OTP email delivery."""

import requests
from flask import current_app


class EmailDeliveryError(RuntimeError):
    """Raised when the configured provider cannot deliver an OTP email."""


def send_otp_email(to_address: str, otp_code: str) -> None:
    """Deliver an OTP through the configured Resend provider only."""
    if not isinstance(to_address, str) or not isinstance(otp_code, str):
        raise EmailDeliveryError("email delivery could not be started")
    provider = current_app.config.get("EMAIL_API_PROVIDER", "").strip().lower()
    api_key = current_app.config.get("EMAIL_API_KEY", "")
    sender = current_app.config.get("EMAIL_FROM_ADDRESS", "")
    if provider != "resend" or not api_key or not sender:
        raise EmailDeliveryError("email delivery is not configured")
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "from": sender,
                "to": [to_address],
                "subject": "Cryptonite verification code",
                "text": f"Your verification code is {otp_code}.",
            },
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise EmailDeliveryError("email delivery failed") from exc
