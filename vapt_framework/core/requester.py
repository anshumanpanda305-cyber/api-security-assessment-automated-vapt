import requests
import json
import urllib.parse
from typing import Dict, Any, Optional, Tuple

class VaptRequester:
    """
    Standardized HTTP client for automated VAPT testing.
    Supports Burp Suite proxy routing and captures raw HTTP request/response PoCs.
    """
    def __init__(self, base_url: str, proxy: Optional[str] = None, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.timeout = timeout
        self.proxy = proxy

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            # Disable SSL verify if proxying via Burp Suite self-signed CA
            self.session.verify = False
            # Suppress InsecureRequestWarning when proxying via Burp
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        token: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Tuple[requests.Response, str, str]:
        """
        Executes an HTTP request and captures raw request & response strings for PoC reporting.
        Returns: (Response, raw_poc_request_str, raw_poc_response_str)
        """
        url = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"
        req_headers = dict(headers or {})
        
        if token:
            req_headers["Authorization"] = f"Bearer {token}"

        req_timeout = timeout or self.timeout

        # Execute request
        response = self.session.request(
            method=method.upper(),
            url=url,
            headers=req_headers,
            params=params,
            json=json_data,
            data=data,
            timeout=req_timeout
        )

        # Build raw HTTP Request string for PoC / Burp Suite Repeater
        parsed_url = urllib.parse.urlparse(response.request.url)
        path_query = parsed_url.path
        if parsed_url.query:
            path_query += f"?{parsed_url.query}"

        poc_request_lines = [f"{method.upper()} {path_query} HTTP/1.1"]
        poc_request_lines.append(f"Host: {parsed_url.netloc}")
        for k, v in response.request.headers.items():
            poc_request_lines.append(f"{k}: {v}")
        poc_request_lines.append("")
        if response.request.body:
            body_str = response.request.body
            if isinstance(body_str, bytes):
                body_str = body_str.decode("utf-8", errors="replace")
            poc_request_lines.append(body_str)

        poc_request_str = "\n".join(poc_request_lines)

        # Build raw HTTP Response string for PoC
        poc_response_lines = [f"HTTP/1.1 {response.status_code} {response.reason}"]
        for k, v in response.headers.items():
            poc_response_lines.append(f"{k}: {v}")
        poc_response_lines.append("")
        
        # Format body preview
        try:
            body_json = response.json()
            poc_response_lines.append(json.dumps(body_json, indent=2))
        except Exception:
            poc_response_lines.append(response.text[:2000])

        poc_response_str = "\n".join(poc_response_lines)

        return response, poc_request_str, poc_response_str
