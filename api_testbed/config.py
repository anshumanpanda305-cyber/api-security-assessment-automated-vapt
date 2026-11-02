import os

class Config:
    """Base API configuration."""
    SECRET_KEY = os.environ.get("VAPT_SECRET_KEY", "app-super-secret-key-production")
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "vapt_testbed.db")
    
    # Toggle between VULNERABLE and SECURE modes
    # Can be toggled via environment variable VAPT_SECURE_MODE=1 or runtime flag
    SECURE_MODE = os.environ.get("VAPT_SECURE_MODE", "0").lower() in ("1", "true", "yes")

    # In vulnerable mode: weak, easily crackable HMAC secret
    # In secure mode: strong 256-bit entropy key
    VULN_JWT_SECRET = "secret123"
    SECURE_JWT_SECRET = "s9F#mK9$vL2!xQ8@zP4*wE1&rT6^yU0(oI3)bN5"

    @classmethod
    def get_jwt_secret(cls):
        return cls.SECURE_JWT_SECRET if cls.SECURE_MODE else cls.VULN_JWT_SECRET
