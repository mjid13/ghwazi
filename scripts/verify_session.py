import sys, os
# Ensure project root is on sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ghwazi.app import create_app

if __name__ == "__main__":
    app = create_app()
    cfg = app.config
    print("SESSION_COOKIE_HTTPONLY=", cfg.get("SESSION_COOKIE_HTTPONLY"))
    print("SESSION_COOKIE_SAMESITE=", cfg.get("SESSION_COOKIE_SAMESITE"))
    print("SESSION_COOKIE_SECURE=", cfg.get("SESSION_COOKIE_SECURE"))
    print("PERMANENT_SESSION_LIFETIME=", cfg.get("PERMANENT_SESSION_LIFETIME"))
    print("SESSION_IDLE_TIMEOUT=", cfg.get("SESSION_IDLE_TIMEOUT"))
