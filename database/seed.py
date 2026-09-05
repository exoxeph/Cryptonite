"""Controlled local setup helpers for local demo data."""

from pathlib import Path
import re

from auth.account_service import create_user, email_lookup_hash
from database import db
from evidence.services import store_evidence
from posts.services import create_post


def create_demo_admin(name: str, email: str, contact: str, password: str) -> int:
    """Create an Admin through the controlled seed path using shared account logic."""
    return create_user(name, email, contact, password, role="admin")


DEMO_PASSWORDS = {
    number: f"CryptoniteDemo{number:02d}!"
    for number in range(1, 31)
}


def seed_demo_data(source_dir: str | Path = "files") -> list[dict]:
    """Import numbered complaint text files and selected image evidence once."""
    source_path = Path(source_dir)
    records = []
    for text_path in sorted(source_path.glob("complaint */text*.txt"), key=_complaint_number):
        number = _complaint_number(text_path)
        email = f"demo{number:02d}@cryptonite.local"
        # Demo accounts use stable email addresses, so lookup by decrypted data is
        # intentionally avoided; the deterministic lookup hash is sufficient.
        existing_user = db.query_one(
            "SELECT id FROM users WHERE email_lookup_hash = ?",
            (email_lookup_hash(email),),
        )
        if existing_user is None:
            user_id = create_user(
                f"Demo Student {number:02d}",
                email,
                f"0170000{number:02d}",
                DEMO_PASSWORDS[number],
                role="student",
            )
        else:
            user_id = existing_user["id"]

        post = db.query_one("SELECT id FROM posts WHERE owner_id = ?", (user_id,))
        if post is None:
            description = text_path.read_text(encoding="utf-8").strip()
            title = _title_from_description(description)
            post_id = create_post(user_id, title, description, anonymous=(number % 5 == 0))
        else:
            post_id = post["id"]

        image_path = _selected_image(text_path.parent, number)
        evidence_added = False
        if image_path is not None and db.query_one(
            "SELECT id FROM evidence WHERE post_id = ?", (post_id,)
        ) is None:
            store_evidence(
                post_id,
                user_id,
                image_path.name,
                image_path.read_bytes(),
                _image_mimetype(image_path),
            )
            evidence_added = True

        records.append(
            {
                "number": number,
                "email": email,
                "password": DEMO_PASSWORDS[number],
                "post_id": post_id,
                "evidence_added": evidence_added,
            }
        )
    return records


def _complaint_number(path: Path) -> int:
    match = re.search(r"complaint (\d+)", str(path.parent), re.IGNORECASE)
    if match is None:
        raise ValueError(f"invalid complaint folder: {path.parent}")
    return int(match.group(1))


def _title_from_description(description: str) -> str:
    title = description.split(".", 1)[0].strip()
    return title[:120].rstrip() or "Demo complaint"


def _selected_image(folder: Path, number: int) -> Path | None:
    if number not in {1, 2}:
        return None
    images = sorted(
        path for path in folder.iterdir() if path.suffix.lower() in {".png", ".jpg", ".jpeg"}
    )
    return images[0] if images else None


def _image_mimetype(path: Path) -> str:
    return {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}[path.suffix.lower()]


def main():
    raise SystemExit("Use 'flask --app app:create_app seed-admin' with explicit credentials.")


if __name__ == "__main__":
    main()
