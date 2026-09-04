Absolutely. Paste the following into something like `project-context.md` and give it to Claude Code alongside your `crypto-plan.md`.

````md
# CSE447 Project Context

## 1. Project Identity

**Course:** CSE447 — Cryptography and Cryptanalysis  
**Project Type:** Lab Project / Secure Web Application  
**Project Title:** **Authority Bridged — Secure Communication Bridge for Student and University Authority**

This project is primarily a **cryptography and security demonstration project**, not a large-scale production social media platform.

The goal is to build a relatively simple web application where students can submit complaints or suggestions to university authorities while demonstrating the cryptographic and security concepts required by CSE447.

The web functionality should remain simple enough that the main focus stays on:

- asymmetric encryption,
- authentication,
- password security,
- two-factor authentication,
- message integrity,
- secure key management,
- role-based access control,
- secure sessions,
- encrypted data storage.

---

# 2. Core Application Idea

Authority Bridged is a secure university complaint/suggestion platform.

Students can:

- register and log in,
- complete two-factor authentication,
- manage their profile,
- create complaints or suggestions,
- optionally post anonymously,
- edit their own posts,
- upload supporting proof/evidence,
- view complaints made by other students,
- upvote other complaints,
- see the status of their complaints,
- privately communicate with an Admin/Authority regarding their own complaint.

Administrators/Authorities can:

- securely log in,
- view complaints,
- acknowledge complaints,
- change complaint status,
- privately communicate with the complaint owner,
- view evidence uploaded for complaints,
- manage appropriate user/account operations,
- perform key-management operations.

The application is intentionally kept relatively small because the cryptographic/security implementation is the main academic objective.

---

# 3. Mandatory CSE447 Requirements

The project must satisfy the following course requirements.

## 3.1 Login and Registration

The system must include:

- user registration,
- user login,
- secure authentication,
- account management.

Sensitive user information must be encrypted before being stored.

It must be decrypted only when an authorized operation needs it.

---

## 3.2 User Information Encryption

Sensitive information such as:

- name,
- username where appropriate,
- email,
- contact information,
- other personal/profile information,

must not be stored as readable plaintext.

The project will primarily use **RSA** for profile/user information.

---

## 3.3 Password Security

Passwords must **never be encrypted or stored in plaintext**.

Passwords must instead use:

- a random salt,
- a cryptographic hash.

Planned approach:

```text
password
+
random salt
↓
SHA-256
↓
stored password hash
````

The database stores:

* password hash,
* password salt.

Login verification works by:

```text
entered password
+
stored salt
↓
hash again
↓
compare against stored hash
```

Do not create any feature that allows a password to be decrypted or recovered.

---

# 4. Two-Factor Authentication

After the password is verified, authentication is not complete yet.

The user must complete a second authentication step.

The planned method is:

## Email OTP

Flow:

```text
Username/email + password
        ↓
Password verified
        ↓
Generate 6-digit OTP
        ↓
Hash OTP before storing it
        ↓
Set short expiration time
        ↓
Send OTP using external email API
        ↓
User enters OTP
        ↓
Verify OTP
        ↓
Create authenticated session
```

Suggested expiration:

```text
5 minutes
```

After successful verification, the OTP should be invalidated.

Do not store the raw OTP permanently.

---

# 5. External API Requirement

The faculty indicated that the project should demonstrate use of an API.

Do **not** use Google/Firebase authentication as the primary login system because that would outsource authentication functionality that the CSE447 project itself is supposed to demonstrate.

Instead, use an external API only for **email delivery of OTP codes**.

Preferred approach:

* Resend,
* Brevo,
* or another simple transactional email API.

The application itself must still:

* generate the OTP,
* store/expire it,
* verify it,
* control authentication.

The external service should only perform:

```text
Application
    ↓
Email API
    ↓
Send OTP email
```

API secrets must never be committed to Git.

Store API keys in environment variables / `.env`.

---

# 6. Roles

There are two main roles.

## Student

A Student can:

* register,
* login,
* complete OTP verification,
* view their profile,
* update their profile,
* create a complaint/suggestion,
* edit their own complaint,
* optionally make the public identity of a post anonymous,
* upload evidence to their own complaint,
* view public complaints,
* upvote complaints,
* see complaint status,
* participate in private chat only for complaints they own.

A Student cannot:

* change another user's post,
* view another user's private evidence,
* manage keys,
* change complaint status,
* access another student's private Admin conversation.

---

## Admin / Authority

An Admin/Authority can:

* login securely,
* complete 2FA,
* view complaints,
* view complaint owner information where authorized,
* view supporting evidence,
* acknowledge a complaint,
* change complaint status,
* communicate privately with the complaint owner,
* perform authorized user-management actions,
* perform cryptographic key-management operations.

---

# 7. Complaint/Post System

A complaint should contain fields such as:

```text
post_id
owner_id
title
description
anonymous
status
created_at
updated_at
key_version
```

Possible complaint statuses:

```text
Pending
Acknowledged
Resolved
```

The Admin can change these statuses.

Students other than the post owner can see the public complaint.

They cannot comment.

They can only:

```text
View
+
Upvote
```

This keeps the application simple and avoids unnecessary social-media functionality.

---

# 8. Anonymous Posting

A student may choose to make their complaint publicly anonymous.

For example, other students may see:

```text
Anonymous Student
```

instead of the owner's name.

Important:

Anonymous mode is only a **display/privacy feature**.

The application must still internally know who owns the post so that:

* the owner can edit it,
* Admin can contact the owner,
* evidence ownership works,
* RBAC can be enforced.

Do not remove the database relationship between the post and owner.

---

# 9. Upvote Feature

Other students should be able to upvote complaints they support.

Students should **not be able to comment** on complaints.

Suggested relation:

```text
upvotes
--------
user_id
post_id
```

There should normally be at most one upvote from the same student for a specific post.

This feature does not need complicated cryptography beyond the normal access-control and storage model.

---

# 10. Supporting Evidence

The original post owner can upload evidence/proof associated with their complaint.

Examples:

* screenshot,
* JPG/JPEG image,
* PNG image,
* PDF.

Keep the allowed file types limited.

Suggested limit:

```text
PDF
PNG
JPG/JPEG
Maximum size around 2 MB
```

Access:

| User                | Can View Evidence |
| ------------------- | ----------------- |
| Original post owner | Yes               |
| Admin/Authority     | Yes               |
| Other students      | No                |

Evidence is considered sensitive data.

Therefore evidence must not remain as a readable plaintext file in storage.

---

# 11. Evidence Encryption

Because the project prohibits symmetric encryption for application data, use **RSA-based block encryption** for evidence files.

Conceptual flow:

```text
Uploaded file
     ↓
Read bytes
     ↓
Split into RSA-compatible chunks
     ↓
RSA encrypt each chunk
     ↓
Store encrypted bytes
```

The stored file should look like:

```text
evidence_12.enc
```

rather than a directly usable:

```text
evidence.jpg
```

When an authorized user wants to view evidence:

```text
RBAC authorization
       ↓
Read encrypted evidence
       ↓
Find RSA key version
       ↓
RSA decrypt chunks
       ↓
Reconstruct original file
       ↓
Return to authorized user
```

Do not permanently create plaintext copies of evidence in the project storage directory.

Temporary decrypted data should exist only for the minimum time necessary.

---

# 12. Cryptography Restrictions

This requirement is extremely important.

## All encryption algorithms must be implemented from scratch.

Do NOT use libraries such as:

```text
cryptography
PyCryptodome RSA encryption
Fernet
OpenSSL encryption wrappers
Flask encryption plugins
```

for the actual RSA/ECC encryption operations.

Framework/library functionality may still be used for normal tasks such as:

* Flask routing,
* SQLite access,
* HTML rendering,
* random number generation,
* HTTP/API calls,
* file handling.

The cryptographic algorithms required by the course must be visibly implemented in our own source code.

The project must exclusively use **asymmetric encryption algorithms for application-data encryption**.

Symmetric encryption such as:

* AES,
* DES,
* 3DES,
* ChaCha20,

must NOT be introduced.

---

# 13. Required Asymmetric Algorithms

At least two different asymmetric encryption algorithms must be used for different purposes.

Our final design uses:

```text
RSA
+
ECC
```

They must not simply duplicate each other's role.

---

# 14. RSA Purpose

RSA is primarily responsible for:

## User/Profile Data

Examples:

```text
name
email
contact information
personal/profile details
```

and:

## Evidence Files

Evidence is encrypted using RSA block/chunk encryption.

RSA may also be used by the Key Management Module to protect cryptographic key material.

---

# 15. RSA Implementation

RSA must be implemented manually.

Core components should include:

```text
prime generation/selection
p
q

n = p × q

φ(n) = (p - 1)(q - 1)

choose e

d = e⁻¹ mod φ(n)
```

Public key:

```text
(e, n)
```

Private key:

```text
(d, n)
```

Encryption:

```text
C = M^e mod n
```

Decryption:

```text
M = C^d mod n
```

Modular exponentiation should be implemented explicitly rather than relying on an RSA library.

Padding/chunking logic must be handled by our implementation.

Do not design RSA assuming that an entire large string/file can be converted to one integer and encrypted at once.

---

# 16. ECC Purpose

ECC is used for communication/content-oriented information.

Planned ECC-protected data includes:

* complaint title,
* complaint description,
* Admin response,
* private Admin ↔ post-owner chat messages.

Use an educational **EC-ElGamal-style encryption scheme** rather than ECIES because ECIES normally introduces a symmetric cipher, which conflicts with the project constraint.

---

# 17. ECC / EC-ElGamal Concept

ECC operates on points on an elliptic curve.

Private key:

```text
d
```

Generator point:

```text
G
```

Public key:

```text
Q = dG
```

For plaintext represented by point `M`, choose random ephemeral `k`.

Encryption:

```text
C1 = kG

C2 = M + kQ
```

Ciphertext:

```text
(C1, C2)
```

Decryption:

```text
M = C2 - dC1
```

because:

```text
dC1 = d(kG)
     = k(dG)
     = kQ
```

and therefore:

```text
C2 - dC1
=
M + kQ - kQ
=
M
```

ECC arithmetic including:

* point addition,
* point doubling,
* scalar multiplication,
* modular inverse,

must be implemented manually.

---

# 18. Encoding Text for ECC

ECC encrypts points, not strings.

For this educational implementation, text can be converted to bytes.

For each byte:

```text
byte value = 0...255
```

map the byte to a known curve point derived from the generator.

For example:

```text
M_byte = (byte + 1)G
```

A precomputed mapping can associate byte values with curve points.

Example:

```text
'A'
ASCII 65
↓
66G
↓
ECC point
```

After decryption, the point can be mapped back to the original byte.

The implementation does not need to be optimized for production-scale cryptography.

The goal is correctness and demonstrability for CSE447.

---

# 19. Message Authentication Code

The faculty specifically wants MAC demonstrated through the private Admin ↔ Student communication feature.

Use:

# HMAC-SHA256

HMAC is used for **integrity**, not confidentiality.

ECC answers:

```text
Can an unauthorized person read the message?
```

HMAC answers:

```text
Has someone modified the message?
```

---

# 20. Private Admin ↔ Post Owner Chat

Only:

```text
Post Owner
↔
Admin/Authority
```

should be able to access this conversation.

Other students cannot access it.

Each chat conversation belongs to a complaint.

Possible message fields:

```text
message_id
post_id
sender_id
receiver_id
ciphertext
mac
ecc_key_version
timestamp
```

---

# 21. Chat Encryption + MAC Flow

Sending:

```text
Plaintext message
       ↓
ECC encryption
       ↓
Ciphertext
       ↓
Generate HMAC
       ↓
Store ciphertext + MAC
```

Calculate the MAC over important message metadata and ciphertext.

Suggested MAC input:

```text
post_id
||
sender_id
||
receiver_id
||
timestamp
||
ciphertext
```

This prevents both modification of the ciphertext and moving a valid ciphertext/MAC pair into a different conversation context.

---

# 22. Chat Verification Flow

When loading a message:

```text
Retrieve ciphertext + stored MAC
             ↓
Recalculate HMAC
             ↓
Compare MACs
        /             \
      valid          invalid
        ↓               ↓
ECC decrypt      DO NOT decrypt
        ↓               ↓
display          integrity warning
```

If the database message is manually modified, MAC verification should fail.

This should be demonstrable during the project presentation.

Example message:

```text
Message integrity verification failed.
Possible unauthorized modification detected.
```

---

# 23. HMAC Implementation

Do not simply call a complete HMAC library function and claim HMAC was implemented from scratch.

Implement the HMAC construction manually.

Conceptually:

```text
HMAC(K, m)
=
H(
    (K' XOR opad)
    ||
    H(
        (K' XOR ipad)
        ||
        m
    )
)
```

Implementation includes:

* key normalization,
* inner pad,
* outer pad,
* XOR,
* inner hash,
* outer hash.

Using an underlying SHA-256 hash implementation/library may be acceptable unless the faculty explicitly requires SHA-256 itself to be written from scratch.

Do NOT use HMAC as encryption.

---

# 24. Key Management Module

A dedicated module must handle:

* key generation,
* key storage,
* key retrieval,
* key distribution/use,
* key versioning,
* key rotation,
* retirement/revocation.

Do not scatter key-handling logic randomly throughout Flask routes.

Prefer something conceptually like:

```text
crypto/
    rsa.py
    ecc.py
    hmac_utils.py
    key_manager.py
```

---

# 25. Key Storage

Private keys must not be stored as readable plaintext in SQLite.

Use a separate root/master asymmetric key for protecting key material.

Concept:

```text
Root / Master RSA Key
          ↓
protects
          ↓
Application cryptographic keys
```

The database may contain something like:

```text
key_id
algorithm
purpose
version
public_key
encrypted_private_key
status
created_at
```

Possible purposes:

```text
RSA_PROFILE
RSA_EVIDENCE
ECC_POSTS
ECC_CHAT
HMAC_CHAT
HMAC_SESSION
```

Do not hard-code private keys inside source files.

---

# 26. Root Key

The root/master private key is the project's root of trust.

Do not store it in SQLite.

Do not commit it to Git.

It may be loaded through:

```text
environment variable
```

or a protected development configuration outside the repository.

Example:

```text
.env
```

must be included in:

```text
.gitignore
```

The report should clearly explain that in a production system this root key would normally be handled through a secure KMS/HSM, but this project uses a simplified local model appropriate for an academic implementation.

---

# 27. Key Rotation

Key rotation must not make existing encrypted data impossible to decrypt.

Therefore every encrypted record should store which key version encrypted it.

Example:

```text
post:
    ciphertext = ...
    key_version = 1
```

Suppose the active ECC key is:

```text
ECC v1
```

After rotation:

```text
ECC v1 → RETIRED
ECC v2 → ACTIVE
```

New records use:

```text
ECC v2
```

Old records retain:

```text
key_version = 1
```

and are decrypted using ECC v1.

Old private keys must therefore remain available for decryption while old ciphertext still exists.

---

# 28. Key Lifecycle

Suggested statuses:

```text
ACTIVE
RETIRED
REVOKED
```

Meaning:

## ACTIVE

Used for:

* new encryption,
* decryption.

## RETIRED

No longer used for new encryption.

Still available for decrypting records created with that version.

## REVOKED

No longer usable.

A key should only become fully revoked/deleted after affected data has been safely migrated/re-encrypted if necessary.

---

# 29. Key Rotation Flow

Example:

```text
ECC Key v1 ACTIVE
        ↓
Admin requests rotation
        ↓
Generate ECC Key v2
        ↓
v2 becomes ACTIVE
        ↓
v1 becomes RETIRED
```

From that point:

```text
New posts → ECC v2

Old posts → ECC v1
```

The `key_version` field determines which key is used during decryption.

---

# 30. Role-Based Access Control

Every sensitive Flask route must verify authorization server-side.

Do not rely only on hiding UI buttons.

Examples:

## Students can:

```text
create own post
edit own post
upload evidence to own post
view public posts
upvote posts
view own private Admin conversation
view own evidence
```

## Students cannot:

```text
edit another student's post
access another student's evidence
access another student's private chat
change complaint status
manage keys
perform Admin operations
```

## Admin can:

```text
view complaints
view protected evidence
acknowledge complaint
change complaint status
chat with owner
perform authorized key-management operations
```

---

# 31. Permission Matrix

Conceptually:

| Action                   |    Post Owner | Other Student |                      Admin |
| ------------------------ | ------------: | ------------: | -------------------------: |
| View public post         |           Yes |           Yes |                        Yes |
| Create complaint         |           Yes |           Yes |                   Optional |
| Edit own post            |           Yes |            No |                As designed |
| Edit someone else's post |            No |            No | Only if explicitly allowed |
| Upvote                   |           Yes |           Yes |                   Optional |
| Comment publicly         |            No |            No |                         No |
| Upload evidence          | Own post only |            No |                         No |
| View evidence            |      Own post |            No |                        Yes |
| Acknowledge post         |            No |            No |                        Yes |
| Change status            |            No |            No |                        Yes |
| Private chat             | Own post only |            No |                        Yes |
| Manage keys              |            No |            No |                        Yes |

---

# 32. Secure Session Management

A session must only be created **after both authentication factors succeed**.

Flow:

```text
Password verified
       ↓
OTP verified
       ↓
Generate new session
```

Use a cryptographically random session identifier.

Session information should contain/track:

```text
session ID
user ID
expiration
active/revoked status
```

---

# 33. Session Token Integrity

Use HMAC to protect session-token information.

Conceptually:

```text
session_id
||
user_id
||
expiry
```

is signed using:

```text
HMAC-SHA256
```

On every authenticated request:

```text
Read session
      ↓
Verify HMAC/signature
      ↓
Check expiration
      ↓
Check active status
      ↓
Authorize request
```

Do not trust a client-controlled user ID or role without server-side verification.

---

# 34. Session-Hijacking Protections

Implement reasonable protections including:

* random session IDs,
* regenerating the session after successful authentication,
* expiration,
* logout invalidation,
* server-side session checks,
* HttpOnly cookies,
* SameSite cookies,
* Secure cookies when HTTPS is used.

Logout should invalidate the server-side session rather than merely removing a browser cookie.

---

# 35. Database

Use:

# SQLite

SQLite is local and appropriate for this academic project.

Do not over-engineer the database layer.

Possible tables:

```text
users
posts
upvotes
evidence
chat_messages
keys
sessions
otp_codes
```

---

# 36. Suggested Users Table

Conceptual structure:

```text
users
-----
id
encrypted_name
encrypted_email
encrypted_contact
password_hash
password_salt
role
profile_key_version
created_at
```

Sensitive profile fields should not appear as plaintext inside the raw database.

---

# 37. Suggested Posts Table

```text
posts
-----
id
owner_id
encrypted_title
encrypted_description
anonymous
status
ecc_key_version
created_at
updated_at
```

`owner_id` may remain metadata because it is required for relationships and RBAC.

The actual sensitive content must be encrypted.

---

# 38. Suggested Evidence Table

```text
evidence
--------
id
post_id
owner_id
encrypted_filename
encrypted_file_path
rsa_key_version
created_at
```

The actual file contents must exist as encrypted data in storage.

---

# 39. Suggested Chat Table

```text
chat_messages
-------------
id
post_id
sender_id
receiver_id
ciphertext
mac
ecc_key_version
created_at
```

MAC must be verified before decrypting/displaying the message.

---

# 40. Suggested Keys Table

```text
keys
----
id
algorithm
purpose
version
public_key
encrypted_private_key
status
created_at
retired_at
```

Never store sensitive private-key material as readable plaintext.

---

# 41. Suggested Sessions Table

```text
sessions
--------
id
session_id_hash
user_id
expires_at
active
created_at
```

The exact design can change, but server-side revocation must be possible.

---

# 42. Suggested OTP Table

```text
otp_codes
---------
id
user_id
otp_hash
expires_at
used
created_at
```

Do not permanently store raw OTP codes.

---

# 43. What Must Be Encrypted

Sensitive application content includes:

```text
user/profile information
complaint title
complaint description
Admin responses
private chat message content
uploaded evidence
sensitive cryptographic key material
```

The database should visibly contain ciphertext for these values.

This is important because the final report requires evidence showing that sensitive records are encrypted at rest.

---

# 44. What Does Not Necessarily Need Encryption

Operational metadata may remain readable when necessary:

```text
database IDs
foreign-key relationships
timestamps
anonymous flag
complaint status
key version
role identifier
upvote relationship
```

Do not encrypt every database integer simply for the sake of encryption.

The important requirement is that sensitive/critical content cannot be read directly after database compromise.

---

# 45. Required Demonstrations

The finished project should make the following demonstrations easy.

## Demo 1 — Registration

Show:

```text
register user
↓
open SQLite
↓
name/email/contact are ciphertext
↓
password is hash + salt
```

---

## Demo 2 — Login + 2FA

Show:

```text
password
↓
email OTP
↓
successful login
```

---

## Demo 3 — Post Encryption

Create:

```text
Broken AC in CSE Lab
```

Then show the SQLite record contains ECC ciphertext rather than the plaintext title/description.

---

## Demo 4 — Anonymous Post

Create an anonymous complaint.

Other students see:

```text
Anonymous Student
```

but the application still correctly associates the post internally with its owner.

---

## Demo 5 — Upvote

Login as another Student and upvote the complaint.

The Student cannot comment.

---

## Demo 6 — Evidence

Upload an image/PDF.

Show that:

```text
Other Student → denied

Post Owner → allowed

Admin → allowed
```

and the stored file is encrypted.

---

## Demo 7 — Complaint Acknowledgement

Admin changes:

```text
Pending
↓
Acknowledged
↓
Resolved
```

---

## Demo 8 — Private Chat

Admin communicates directly with the complaint owner.

Another Student must be denied access.

---

## Demo 9 — MAC Tampering Detection

Create a private chat message.

Then manually modify its stored ciphertext/MAC-related data in SQLite.

Reload the conversation.

Expected result:

```text
Integrity verification failed.
```

The corrupted message must not simply be decrypted/displayed as if it were valid.

---

## Demo 10 — Key Rotation

Create data using:

```text
Key Version 1
```

Rotate key.

Show:

```text
Version 1 → RETIRED
Version 2 → ACTIVE
```

Create new data.

Show:

```text
Old data → v1
New data → v2
```

Then demonstrate that both still decrypt correctly.

---

# 46. Technology Stack

Use:

## Backend

```text
Python
Flask
```

## Database

```text
SQLite
```

## Frontend

```text
HTML
CSS
Jinja2 templates
Bootstrap if useful
```

## Testing

```text
pytest
```

## External API

Transactional email API used for OTP delivery.

Do not make the frontend complicated.

The UI only needs to be clean and functional enough to demonstrate the security features.

---

# 47. Suggested Project Structure

A reasonable structure could be:

```text
authority-bridged/
│
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
├── crypto/
│   ├── __init__.py
│   ├── rsa.py
│   ├── ecc.py
│   ├── hmac_custom.py
│   ├── hashing.py
│   └── key_manager.py
│
├── auth/
│   ├── routes.py
│   ├── otp.py
│   └── sessions.py
│
├── posts/
│   ├── routes.py
│   └── services.py
│
├── chat/
│   ├── routes.py
│   └── services.py
│
├── evidence/
│   ├── routes.py
│   └── services.py
│
├── database/
│   ├── db.py
│   ├── schema.sql
│   └── seed.py
│
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   ├── dashboard.html
│   ├── posts.html
│   ├── post_detail.html
│   ├── create_post.html
│   ├── profile.html
│   ├── chat.html
│   └── admin/
│
├── static/
│   ├── css/
│   └── js/
│
├── encrypted_uploads/
│
└── tests/
```

This structure is only a recommendation.

Claude Code may improve it, but cryptographic code should remain separated from Flask route logic.

---

# 48. Development Principles for Claude Code

When implementing this project, follow these rules.

## Rule 1 — Do not silently change the cryptographic design

The chosen architecture is:

```text
RSA → profiles + evidence + key protection

ECC / EC-ElGamal → posts + responses + chat

HMAC-SHA256 → chat integrity + session integrity

SHA-256 + salt → password protection

Email OTP → second authentication factor

Versioned Key Manager → rotation
```

If a technical issue requires changing this design, explain the problem before changing it.

---

## Rule 2 — Do not introduce symmetric encryption

Do not solve difficult encryption problems by introducing:

```text
AES
Fernet
DES
ChaCha20
```

The assignment explicitly prohibits symmetric encryption for the required application-data encryption.

---

## Rule 3 — Do not replace our algorithms with library crypto

Do not replace from-scratch RSA/ECC with:

```python
RSA.generate(...)
ECC.generate(...)
Fernet(...)
```

or similar cryptographic library calls.

The implementation must demonstrate the underlying algorithms.

---

## Rule 4 — Keep everything understandable

This is a university cryptography course project.

Prefer:

* readable code,
* small functions,
* comments explaining cryptographic steps,
* clear variable names,
* demonstrable algorithms,

over production-scale abstraction.

The students must be able to explain the code during evaluation.

---

## Rule 5 — Do not over-engineer

Do not introduce unless absolutely necessary:

```text
Docker
Redis
Celery
Kafka
React
Next.js
microservices
Kubernetes
cloud databases
complex frontend frameworks
```

The intended stack is Flask + SQLite + simple HTML/CSS.

---

## Rule 6 — Security checks must be server-side

Never assume that hiding a button makes an action secure.

Every protected route must verify:

```text
authentication
role
ownership
authorization
```

on the backend.

---

## Rule 7 — Preserve evidence for the final report

The final CSE447 report requires screenshots and explanation of each security component.

Implementation should therefore make it easy to demonstrate:

* encrypted database fields,
* password hashing/salting,
* OTP,
* RSA,
* ECC,
* MAC,
* key rotation,
* RBAC,
* secure sessions,
* encrypted evidence storage.

Do not hide all security behavior behind abstractions that make it impossible to explain or demonstrate.

---

# 49. Required Report Sections

The final report template expects documentation for:

1. Introduction and System Overview
2. Login and Registration Module
3. User Data Encryption and Decryption
4. Password Hashing and Salting
5. Two-Factor Authentication
6. Key Management Module
7. Post and Profile Management
8. Data Storage Security
9. Message Authentication Code
10. Role-Based Access Control
11. Secure Session Management
12. GitHub Repository and Project Structure
13. Conclusion

Implementation decisions should make these sections straightforward to complete later.

---

# 50. Architecture Overview

The intended high-level flow is:

```text
                      AUTHORITY BRIDGED
                              │
              ┌───────────────┴───────────────┐
              │                               │
       AUTHENTICATION                    APPLICATION
              │                               │
      Registration/Login                 Student Post
              │                               │
     RSA profile encryption              ECC encryption
              │                               │
    Salted password hash              Public post listing
              │                               │
        Email OTP API                Other students upvote
              │                               │
       Session creation                Evidence upload
              │                               │
       HMAC-protected                   RSA encryption
          session                            │
                                      Admin accesses
                                            │
                                      Acknowledges
                                            │
                                   Changes post status
                                            │
                                Private Admin ↔ Owner Chat
                                            │
                                  ECC confidentiality
                                            +
                                      HMAC integrity
```

---

# 51. Cryptographic Responsibility Map

| Requirement                    | Implementation                                |
| ------------------------------ | --------------------------------------------- |
| User/profile confidentiality   | RSA                                           |
| Complaint confidentiality      | ECC / EC-ElGamal                              |
| Admin response confidentiality | ECC / EC-ElGamal                              |
| Private chat confidentiality   | ECC / EC-ElGamal                              |
| Evidence confidentiality       | RSA block encryption                          |
| Password protection            | Salt + SHA-256                                |
| Chat integrity                 | HMAC-SHA256                                   |
| Session integrity              | HMAC-SHA256                                   |
| Second factor                  | Email OTP                                     |
| API usage                      | Email delivery API                            |
| Key lifecycle                  | Versioned Key Management Module               |
| Authorization                  | RBAC                                          |
| Session protection             | Random session + expiry + HMAC + invalidation |

---

# 52. Current Scope — Do Not Expand Without Reason

The planned application DOES include:

```text
Student/Admin authentication
2FA
profiles
complaints/suggestions
anonymous posting
upvotes
evidence
complaint status
Admin acknowledgement
private Admin-owner chat
RSA
ECC
HMAC
key rotation
RBAC
secure sessions
email API
```

The project DOES NOT need:

```text
public comments
student-to-student chat
social-media feeds
friend systems
notifications system beyond OTP
complex analytics
AI features
audit-log dashboard unless later required
Google social login
Firebase authentication
payment systems
mobile apps
```

Do not expand scope unless a course requirement specifically requires it.

---

# 53. Main Goal

The goal is NOT to build the most advanced complaint-management platform possible.

The goal is to build a **small, understandable and demonstrable secure application where every CSE447 cryptography requirement has a clear practical purpose.**

The final system should make it easy for the group to explain:

```text
Why RSA exists
Why ECC exists
Why both are different
Why passwords are hashed rather than encrypted
What salt does
What OTP does
What a MAC does
How tampering is detected
How key rotation works
Why old keys cannot immediately be deleted
How encrypted evidence works
How RBAC prevents unauthorized access
How sessions are protected
```

Security/course compliance takes priority over adding extra website features.

---

# 54. Additional Claude Code Instruction

Before implementing a major security component, first inspect:

```text
project-context.md
crypto-plan.md
```

Treat these files as the source of truth for the project architecture.

When working on a crypto/security module:

1. explain what part of the project requirement it satisfies,
2. keep the implementation understandable,
3. do not silently use prohibited crypto libraries,
4. do not introduce symmetric encryption,
5. preserve compatibility with the key-versioning system,
6. include useful comments,
7. ensure the feature can later be demonstrated in the final report.

If an implementation decision conflicts with the CSE447 requirements or the established crypto plan, stop and identify the conflict rather than silently redesigning the system.

```

I made this intentionally **much more complete than the proposal**: Claude Code can use this as its project-wide source of truth, while your `crypto-plan.md` can hold the deeper cryptography-specific decisions.
```
