"""
One-time helper: generates a random secret for config.yaml's cookie.key.

Run:
    python generate_cookie_key.py

Copy the printed value into config.yaml under cookie.key.
"""

import secrets

if __name__ == "__main__":
    print(secrets.token_hex(32))