Yeah. At this point I’d **freeze the security design** so you don’t keep changing approaches during implementation. Based on your proposal plus what the report template will make you demonstrate, this is the version I’d use.

The template specifically expects you to document RSA/ECC separately, explain how the two are used differently, show protected key storage/rotation, demonstrate MAC verification, and explain session-token protection.   

## Final security design

| Part                       | Final approach                                                   |
| -------------------------- | ---------------------------------------------------------------- |
| User/profile data          | **RSA encryption**                                               |
| Evidence PDF/image         | **RSA encryption in blocks**                                     |
| Complaint/post text        | **ECC / EC-ElGamal**                                             |
| Admin response             | **ECC / EC-ElGamal**                                             |
| Private Admin ↔ owner chat | **ECC + HMAC**                                                   |
| Password                   | **SHA-256 + random salt**                                        |
| 2FA                        | **6-digit email OTP**                                            |
| External API               | **Email API used to deliver OTP**                                |
| Key storage                | Private keys encrypted/wrapped using a separate root RSA key     |
| Key rotation               | Versioned keys; old keys retained temporarily for old ciphertext |
| Sessions                   | Random session token + HMAC verification + expiry                |
| Roles                      | Student / Admin-Authority                                        |
| Database                   | SQLite                                                           |
| Framework                  | Flask                                                            |

---

# 1. RSA — what exactly uses it

Keep RSA primarily for **user/profile information** as you already proposed:

```text
name
email
phone/contact info
other profile information
```

Flow:

```text
Registration
    ↓
plaintext profile fields
    ↓
RSA Encrypt
    ↓
SQLite stores ciphertext
```

On profile view:

```text
SQLite ciphertext
    ↓
RSA Decrypt
    ↓
authorized user sees plaintext
```

This lines up exactly with the report's requirement to identify which fields are encrypted and how they're decrypted on retrieval. 

### RSA implementation

Use educational textbook RSA, implemented from scratch:

```text
p and q ≈ 128-bit distinct primes
n = p × q ≈ 256-bit modulus
φ(n) = (p-1)(q-1)
e = 11, with gcd(e, φ(n)) = 1
d = e⁻¹ mod φ(n)
Public key  = (e,n)
Private key = (d,n)
```

Encryption is `C = M^e mod n` and decryption is `M = C^d mod n`, evaluated with
Python's built-in three-argument modular `pow()` operation as demonstrated in
the course lab. Arbitrary bytes are split
into chunks of `(n.bit_length() - 1) // 8` bytes and stored in the `TBR1`
container with plaintext length, chunk size, block count, and ciphertext blocks.
There is no padding; textbook RSA is deterministic, malleable, and not suitable
for production deployment. Existing OAEP ciphertext must be discarded during
the documented development-data reset.

---

# 2. ECC — complaints and messages

Keep your distinction:

**RSA = identity/profile/evidence**

**ECC = communication/content**

ECC handles:

```text
Complaint title
Complaint description
Authority response
Private chat messages
```

I recommend **EC-ElGamal**, because it is genuinely asymmetric ECC encryption and doesn't secretly introduce symmetric encryption like ECIES normally does.

Conceptually:

Admin/student has:

$$
Q=dG
$$

where:

* \(d\) = private key
* \(G\) = generator point
* \(Q\) = public key

For plaintext represented as point \(M\):

$$
C_1=kG
$$

$$
C_2=M+kQ
$$

Ciphertext is:

$$
(C_1,C_2)
$$

Decryption:

$$
M=C_2-dC_1
$$

because:

$$
dC_1=d(kG)=k(dG)=kQ
$$

and therefore:

$$
C_2-dC_1=M+kQ-kQ=M
$$

That's a very nice algorithm for you guys to demonstrate in CSE447 because it directly uses the ECC mathematics you're studying.

### But how does text become a curve point?

Keep this educational and manageable.

Convert the message into bytes:

```text
"Hi"
↓
72, 105
```

Then map every possible byte to a multiple of \(G\):

$$
M=(byte+1)G
$$

So:

```text
72  → 73G
105 → 106G
```

You can precompute a table for values `0–255`.

After decryption, you get the point back and look it up in the table to recover the byte.

It's inefficient compared with real-world cryptography, but for a **CSE447 demonstration using only asymmetric encryption**, it's straightforward and easy to explain.

---

# 3. Evidence uploads

This is where I would **not use ECC**.

If someone uploads:

```text
evidence.pdf
photo.jpg
screenshot.png
```

you'd have thousands/millions of bytes. Encrypting every byte as an elliptic-curve point would become ridiculous.

Instead:

### Use RSA block encryption for evidence files.

Student uploads:

```text
proof.jpg
        ↓
Read raw bytes
        ↓
Split into RSA-sized blocks
        ↓
RSA encrypt every block
        ↓
Store encrypted file
```

Something like:

```text
uploads/
   evidence_17.enc
   evidence_21.enc
```

The file in the filesystem is **ciphertext**, not a usable JPG/PDF.

SQLite stores something like:

```text
evidence_id
post_id
owner_id
encrypted_filename
encrypted_file_path
key_version
created_at
```

When the owner/Admin clicks evidence:

```text
RBAC check
↓
Read encrypted file
↓
RSA decrypt blocks
↓
temporarily return original PDF/image
```

### Who gets access?

| Person          | View evidence |
| --------------- | ------------: |
| Post owner      |             ✅ |
| Admin/Authority |             ✅ |
| Other students  |             ❌ |

Other students see the public complaint and can upvote it, but **not the evidence**.

I'd also restrict evidence to:

```text
PDF
PNG
JPG/JPEG
```

and set a small limit such as **2 MB**.

This prevents the course project from turning into a file-storage project.

---

# 4. MAC — finalize this as HMAC

Use:

## **HMAC-SHA256**

Do **not use CBC-MAC** here.

CBC-MAC depends on a symmetric block cipher, while your project explicitly says symmetric encryption isn't allowed.

HMAC doesn't encrypt anything. It provides **integrity/authentication**, exactly what your faculty asked you to demonstrate.

The report explicitly allows HMAC and asks you to explain when verification happens. 

Your private chat works like this:

```text
Student message:
"The projector has been broken for 3 weeks."

             ↓

ECC encryption

             ↓

Ciphertext

             ↓

HMAC-SHA256
      using MAC secret

             ↓

SQLite:

ciphertext
MAC
sender
post_id
timestamp
```

I'd calculate the MAC over more than just the message:

```text
post_id
+
sender_id
+
recipient_id
+
timestamp
+
ciphertext
```

So an attacker can't move one valid message to another conversation without the MAC becoming invalid.

### When reading the message

Do this order:

```text
Retrieve ciphertext + stored MAC
             ↓
Recalculate HMAC
             ↓
Compare
      /             \
 Match              Fail
   ↓                  ↓
Decrypt ECC       DO NOT decrypt
   ↓              Show tampering warning
Display
```

This is basically:

## Encrypt → MAC → Store

and

## Retrieve → Verify MAC → Decrypt

That's very easy to demonstrate to your faculty.

You can literally manually change one ciphertext value in SQLite during your presentation and then show:

> ⚠ Message integrity verification failed.

That will make the purpose of MAC obvious.

---

# 5. HMAC implementation

Do **not** call Python's `hmac.new()` and call it a day if the report says from-scratch MAC.

Implement the HMAC construction yourselves:

$$
HMAC(K,m)=H((K'\oplus opad)\parallel H((K'\oplus ipad)\parallel m))
$$

You'll implement:

```text
Key normalization
ipad
opad
XOR
inner hash
outer hash
```

Using SHA-256 underneath.

So you can truthfully explain that **your HMAC construction itself is implemented manually** rather than using Python's HMAC function.

---

# 6. Key storage

This one needed the most clarification.

Don't do:

```text
private_key = "123456789..."
```

inside SQLite.

Instead have a separate **Root/Master RSA key pair**.

Call it:

```text
Key Encryption Key (KEK)
```

It exists only for protecting other keys.

Architecture:

```text
                  ROOT RSA KEY
                       │
                protects/wraps
                       ↓
       ┌───────────────┼───────────────┐
       ↓               ↓               ↓
RSA private key   ECC private key   HMAC secret
```

The application keys stored in SQLite are therefore encrypted.

Example key table:

```text
keys

key_id
algorithm
version
public_key
encrypted_private_key
created_at
status
```

Example:

```text
RSA_PROFILE
version = 1
status = RETIRED

RSA_PROFILE
version = 2
status = ACTIVE
```

The **root private key itself should not be in SQLite or GitHub**.

Keep it as an environment secret/configuration value on the project machine:

```text
.env
```

and:

```gitignore
.env
```

That provides your root of trust.

For a production application you'd use something like an HSM/cloud KMS, but that would be massive overkill here.

---

# 7. Key rotation — use versions

This is the clean solution to the issue I mentioned earlier.

Imagine Post 25 was encrypted using:

```text
ECC Key Version 1
```

Then Admin rotates the key.

You generate:

```text
ECC Key Version 2
```

Now:

```text
Version 1 = RETIRED
Version 2 = ACTIVE
```

### New content

Always encrypt using:

```text
ACTIVE key → Version 2
```

### Existing content

Still remembers:

```text
key_version = 1
```

Therefore:

```text
Old post
↓
key_version = 1
↓
Key Manager gets ECC key v1
↓
Decrypt successfully
```

**Do not immediately delete old private keys.**

The report specifically asks you to explain how rotation avoids breaking existing encrypted records. 

So the lifecycle becomes:

```text
ACTIVE
   ↓ rotate
RETIRED
   ↓
still allowed for DECRYPTION only
   ↓
old records eventually re-encrypted with newest key
   ↓
REVOKED / DELETE
```

That is probably the cleanest answer you can give your faculty for key rotation.

---

# 8. Passwords

Keep this simple.

```text
User enters password
↓
Generate random salt
↓
SHA-256(salt || password)
↓
Store:
salt
hash
```

Never:

```text
RSA_encrypt(password)
```

Passwords don't need to be recoverable.

The template specifically expects you to explain the hash function, salt generation/storage, and login verification. 

During login:

```text
Input password
+
stored salt
↓
hash again
↓
compare with stored hash
```

---

# 9. 2FA + your API requirement

This is where I think we can solve **two requirements at once**.

I would **NOT use Firebase Authentication or Google Sign-In**.

Why?

Your course specifically wants you to demonstrate:

```text
Registration
Login
Password hashing
Salt
Encrypted user information
2FA
```

The template even expects you to describe your own registration and login processing. 

If Firebase/Google suddenly handles authentication for you, you're outsourcing the exact thing your project is supposed to demonstrate.

So don't do:

```text
Continue with Google
       ↓
Firebase handles everything
```

It creates more problems than it solves.

---

## Use an Email API for OTP instead

Flow:

```text
Username/password correct
          ↓
Generate random 6-digit OTP

          ↓

482193

          ↓
Store HASH(OTP) + expiration
          ↓
Call external email API
          ↓
User receives:
"Your verification code is 482193"
          ↓
User enters code
          ↓
Verify
          ↓
Create session
```

Now you've satisfied:

**✅ 2FA**

and

**✅ external API usage**

without outsourcing your cryptography.

### API I'd use: Resend

Its current Python documentation includes a very small Python integration and even shows Flask usage directly. ([Resend][1])

Conceptually your Flask code just calls their API to send:

```text
To: student@email.com

Your Authority Bridged verification code is:

482193

Expires in 5 minutes.
```

The **API does not generate or verify the OTP**.

Your application does.

Resend merely acts as:

> email delivery service.

That's an important distinction for your report.

Keep its API key in:

```text
.env
```

not GitHub.

Brevo is another option and also provides a Python API for transactional emails if Resend gives you account/sender issues. ([Brevo API Documentation][2])

---

# 10. OTP implementation

I'd actually change this line from your proposal:

> HMAC-based temporary verification code

to:

> **Email OTP:** After successful password verification, the system generates a random six-digit one-time verification code with a short expiration period. The code is delivered to the user's registered email address through an external email API and must be verified before a login session is granted.

Much simpler.

Store:

```text
otp_hash
otp_expiry
```

not:

```text
otp = "482193"
```

Give it around:

```text
5-minute expiration
```

and invalidate it after successful use.

---

# 11. Sessions

I would also lock this down now.

After password + OTP succeeds:

```text
Generate random session ID
↓
Create expiration time
↓
Generate HMAC over session data
↓
Put token in cookie
```

Something conceptually like:

```text
session_id | expiry | signature
```

where:

$$
signature=HMAC(K_{session},session\_id||expiry||user\_id)
$$

Cookie settings:

```text
HttpOnly = True
SameSite = Lax/Strict
Secure = True     # when HTTPS is available
```

On every authenticated request:

```text
Read cookie
↓
Verify HMAC
↓
Check expiration
↓
Check session is active
↓
Allow request
```

Logout:

```text
invalidate session
+
remove cookie
```

And create a **new session ID only after 2FA succeeds**, which helps prevent session fixation.

This matches the template's explicit expectation that you explain token signing/verification. 

---

# 12. Final data model conceptually

You don't need these exact SQL tables yet, but this should be the architecture:

```text
users
├── id
├── encrypted_name
├── encrypted_email
├── encrypted_contact
├── password_hash
├── password_salt
└── role


posts
├── id
├── owner_id
├── encrypted_title
├── encrypted_description
├── anonymous
├── status
├── key_version
└── timestamp


upvotes
├── user_id
└── post_id


evidence
├── id
├── post_id
├── owner_id
├── encrypted_filename
├── encrypted_file_path
└── rsa_key_version


chat_messages
├── id
├── post_id
├── sender_id
├── ciphertext
├── mac
├── ecc_key_version
├── hmac_key_version
└── created_at

Conversation membership is derived from the post: the post owner and Admin
may access the conversation; everyone else is denied. An Admin response is
an Admin-authored row in `chat_messages`, not a separate post field.


keys
├── id
├── algorithm
├── version
├── public_key
├── encrypted_private_key
├── status
└── created_at


sessions
├── session_id_hash
├── user_id
├── expires_at
└── active
```

Operational metadata like:

```text
post ID
timestamp
status
key version
upvote count
```

does **not need to be encrypted**.

Sensitive content does.

---

## So I'd freeze the project like this

```text
                    AUTHORITY BRIDGED
                           │
          ┌────────────────┴─────────────────┐
          │                                  │
     Authentication                       Application
          │                                  │
   Password + Salt                Complaint / Suggestion
          │                                  │
      Email OTP                         ECC Encrypt
          │                                  │
   Resend API                      Other students view
          │                         + upvote only
      Session                              │
      HMAC                                 │
                                    Evidence upload
                                     RSA Encrypt
                                          │
                                     Admin sees
                                          │
                                      Acknowledge
                                          │
                                Private Admin ↔ Owner
                                          │
                                  ECC Encryption
                                         +
                                       HMAC
```

And cryptographically:

**RSA** → profiles + evidence + key wrapping
**ECC/EC-ElGamal** → posts + responses + private messages
**HMAC-SHA256** → private chat integrity + session-token integrity
**SHA-256 + salt** → passwords
**Email OTP + Resend API** → 2FA/API requirement
**Versioned Key Manager** → rotation without breaking old records

That gives every security technique **one understandable purpose**, which is exactly what will make the report and faculty demonstration much easier.

[1]: https://resend.com/python?utm_source=chatgpt.com "Send emails with Python · Resend"
[2]: https://developers.brevo.com/guides/python?utm_source=chatgpt.com "Python SDK | Brevo API Documentation"
