import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "authority_bridged.db"))

    ROOT_RSA_N = os.getenv("ROOT_RSA_N", "")
    ROOT_RSA_E = os.getenv("ROOT_RSA_E", "")
    ROOT_RSA_D = os.getenv("ROOT_RSA_D", "")
    RSA_PRIME_BITS = _get_int("RSA_PRIME_BITS", 128)
    RSA_PUBLIC_EXPONENT = _get_int("RSA_PUBLIC_EXPONENT", 11)

    EMAIL_API_PROVIDER = os.getenv("EMAIL_API_PROVIDER", "")
    EMAIL_API_KEY = os.getenv("EMAIL_API_KEY", "")
    EMAIL_FROM_ADDRESS = os.getenv("EMAIL_FROM_ADDRESS", "")

    OTP_EXPIRY_SECONDS = _get_int("OTP_EXPIRY_SECONDS", 300)
    OTP_EMAIL_ENABLED = _get_bool("OTP_EMAIL_ENABLED", True)
    OTP_DEV_PRINT_CODE = _get_bool("OTP_DEV_PRINT_CODE", False)
    MAX_EVIDENCE_SIZE_BYTES = _get_int("MAX_EVIDENCE_SIZE_BYTES", 200 * 1024)
    EVIDENCE_UPLOAD_DIR = os.getenv("EVIDENCE_UPLOAD_DIR", str(BASE_DIR / "encrypted_uploads"))

    # Flask's signed cookie is limited to the temporary pending-OTP marker.
    # The authenticated server-revocable cookie uses the frozen environment name.
    SESSION_COOKIE_NAME = "authority_bridged_pending"
    AUTH_SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "authority_bridged_session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = _get_bool("SESSION_COOKIE_SECURE", False)
    SESSION_LIFETIME_SECONDS = _get_int("SESSION_LIFETIME_SECONDS", 3600)
    UI_PREVIEW_ENABLED = _get_bool("UI_PREVIEW_ENABLED", True)
    FACULTY_CRYPTO_TRACE = _get_bool("FACULTY_CRYPTO_TRACE", False)
    FACULTY_CRYPTO_TRACE = _get_bool("FACULTY_CRYPTO_TRACE", False)
