"""Controlled setup scaffold.

Phase 1 intentionally does not create Admin users, demo students, placeholder
password hashes, or plaintext credentials. Admin seeding is added after password
hashing and RSA profile encryption exist.
"""


def main():
    print("Seed scaffold only. No users are created in Phase 1.")


if __name__ == "__main__":
    main()
