"""Controlled local Admin setup, separate from public registration."""

from auth.account_service import create_user


def create_demo_admin(name: str, email: str, contact: str, password: str) -> int:
    """Create an Admin through the controlled seed path using shared account logic."""
    return create_user(name, email, contact, password, role="admin")


def main():
    raise SystemExit("Use 'flask --app app:create_app seed-admin' with explicit credentials.")


if __name__ == "__main__":
    main()
