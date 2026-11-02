import urllib.parse
import socket
import ipaddress

class ScopeValidationError(Exception):
    """Raised when a target URL is outside authorized testing scope."""
    pass

class TargetScopeValidator:
    """
    Enforces ethical boundary guards.
    Strictly restricts scans to localhost or explicitly authorized hosts.
    """
    ALLOWED_LOCAL_HOSTS = {
        "127.0.0.1",
        "localhost",
        "::1",
        "0.0.0.0"
    }

    def __init__(self, authorized_hosts=None):
        self.authorized_hosts = set(self.ALLOWED_LOCAL_HOSTS)
        if authorized_hosts:
            for host in authorized_hosts:
                self.authorized_hosts.add(host.lower().strip())

    def validate_url(self, target_url: str) -> bool:
        """
        Validate whether target URL is authorized.
        Raises ScopeValidationError if not authorized.
        """
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ScopeValidationError(f"Invalid URL format: '{target_url}'. Must include scheme (e.g. http://127.0.0.1:5000)")

        hostname = parsed.hostname
        if not hostname:
            raise ScopeValidationError(f"Could not determine hostname from URL: '{target_url}'")

        hostname = hostname.lower()

        # Check explicit authorized hostnames
        if hostname in self.authorized_hosts:
            return True

        # Check if hostname resolves to a loopback address
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback:
                return True
        except Exception:
            pass

        raise ScopeValidationError(
            f"[SECURITY GUARD TRIGGERED] Target '{target_url}' (Host: {hostname}) is OUTSIDE authorized scope.\n"
            f"By policy and design, this scanner only operates on localhost (127.0.0.1) or explicitly authorized domains.\n"
            f"Authorized targets: {sorted(list(self.authorized_hosts))}"
        )
