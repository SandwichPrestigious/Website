"""
Flask backend for MFA Login System
Wraps the mfa_project.py logic into REST API endpoints.

Run:
    pip install flask pyotp qrcode pillow flask-cors
    python app.py

Endpoints:
    POST /api/login        -> validates credentials, returns QR code + secret
    POST /api/verify-otp   -> verifies TOTP code, returns success/failure
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import pyotp
import qrcode
import io
import base64
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)
CORS(app, supports_credentials=True)

# ── Simulated user database ─────────────────────────────────────────────────
# In production: replace with a real DB (PostgreSQL, MySQL, etc.)
# Password should be hashed with bcrypt/argon2 — plaintext here for demo only.
USERS = {
    "admin@iamproject.com":  {"password": "admin123",  "name": "Admin"},
    "test@iamproject.com":   {"password": "test123",   "name": "TestUser"},
}

# In-memory MFA secret store: { email: secret }
# In production: persist this in your user DB, one row per user.
MFA_SECRETS = {}


@app.route("/api/login", methods=["POST"])
def login():
    """
    Step 1: Validate username + password.
    If valid, generate (or retrieve) a TOTP secret, build a QR code,
    and return the QR image + secret to the frontend for scanning.
    """
    data = request.get_json()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = USERS.get(email)
    if not user or user["password"] != password:
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    # Generate secret once per user; persist across calls so the same QR works
    if email not in MFA_SECRETS:
        MFA_SECRETS[email] = pyotp.random_base32()   # same as mfa_project.py line 7

    secret = MFA_SECRETS[email]

    # Build the otpauth URI (same as mfa_project.py lines 11-12)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="MySecureApp")

    # Generate QR code as base64 PNG (same as mfa_project.py lines 14-15, but in-memory)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Store email in session so /api/verify-otp knows who to verify
    session["pending_email"] = email
    session["user_name"] = user["name"]

    return jsonify({
        "success": True,
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_b64}",
        "name": user["name"],
    })


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    """
    Step 2: Verify the 6-digit TOTP code.
    Mirrors mfa_project.py line 24: totp.verify(code)
    """
    email = session.get("pending_email")
    if not email:
        return jsonify({"success": False, "error": "Session expired. Please log in again."}), 401

    data = request.get_json()
    code = (data.get("code") or "").strip()

    secret = MFA_SECRETS.get(email)
    if not secret:
        return jsonify({"success": False, "error": "No MFA secret found for this account."}), 400

    totp = pyotp.TOTP(secret)
    if totp.verify(code):                            # same check as mfa_project.py line 24
        session.pop("pending_email", None)
        return jsonify({"success": True, "name": session.get("user_name", "User")})
    else:
        return jsonify({"success": False, "error": "Invalid code. Please try again."}), 401


if __name__ == "__main__":
    print("=== MFA Login Server ===")
    print("Demo accounts:")
    for email, u in USERS.items():
        print(f"  {email}  /  {u['password']}")
    print("Running on http://localhost:5000")
    app.run(debug=True, port=5000)
