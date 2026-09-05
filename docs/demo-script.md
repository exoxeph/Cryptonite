# Authority Bridged Demo Script

This script demonstrates that private chat messages are confidential and that
CMAC integrity verification prevents modified ciphertext from being decrypted.
Run it only against a local development or demo database. Never run the
tampering SQL against a shared or production database.

## Chat Integrity Demo

1. Start the application and log in as the complaint owner.
2. Open the complaint's **Private chat** page.
3. Send this message:

   `Please review this complaint.`

4. Reload the chat and confirm the plaintext displays normally.
5. Open the local SQLite database and inspect the message row. The row should
   show metadata and encrypted values, including `ciphertext` and `mac`, but
   not the plaintext:

   ```sql
   SELECT id, post_id, sender_id, ciphertext, mac,
          ecc_key_version, cmac_key_version, created_at
   FROM chat_messages
   ORDER BY id DESC;
   ```

6. Choose the intended `id` from the query result and replace
   `<MESSAGE_ID>` in this targeted statement:

   ```sql
   UPDATE chat_messages
   SET ciphertext = 'tampered'
   WHERE id = <MESSAGE_ID>;
   ```

   The `WHERE` clause is required. This changes only the selected demo row and
   deliberately leaves its original `mac` unchanged.

7. Reload the same chat page. The expected result is exactly:

   `Message integrity verification failed. Possible unauthorized modification detected.`

   The corrupted message plaintext must not appear.

The stored MAC covers `post_id`, `sender_id`, `created_at`, and `ciphertext`.
Originally, `mac = CMAC(context || C)`. After an attacker changes the
ciphertext to `C'` without the `CMAC_CHAT` key, verification recomputes a
different value. The application reports the warning and skips ECC
deserialization and decryption.

The read sequence is:

```text
read stored ciphertext
  -> rebuild MAC input
  -> verify CMAC
  -> mismatch
  -> do not ECC decrypt
  -> show warning
```

To reset the intentionally corrupted local demo state, reset or reseed the
demo database and create a new message. Do not try to repair the row by
manually generating a MAC.

## Session Integrity Cross-check

1. Log in normally and open a protected page.
2. Inspect the authenticated session cookie in the browser's local developer
   tools.
3. Change part of the token or signature in your own local browser cookie.
4. Request the protected page again. The server must reject the session and
   require login again.
5. Log in normally afterward.

Chat integrity uses `CMAC_CHAT` for stored message rows. Session integrity uses
`CMAC_SESSION` for authenticated session tokens. They are separate key
purposes; neither uses Flask `SECRET_KEY`, and no secret key material should be
shown during the demonstration.

## Evidence to Capture

Capture both states for the report:

- Before tampering: normal plaintext and no warning.
- After tampering: the exact warning and no plaintext.

The database screenshot may show `id`, `post_id`, `sender_id`, `ciphertext`,
`mac`, `ecc_key_version`, `cmac_key_version`, and `created_at`. Do not include
CMAC secrets, ECC private scalars, RSA private values, the root private key, or
Flask `SECRET_KEY`.
