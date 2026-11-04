"""HTTP client for the FLOWGUARD assessment engine."""

from __future__ import annotations

import time
import re
from typing import Any
from urllib.parse import unquote, urlsplit

import requests

from .config import FlowGuardConfig
from .redaction import redact_text, sanitize_value
from .schemas import ApiResult


class FlowGuardClient:
    """Thin, thread-safe wrapper around the ShopZone HTTP API.

    A new requests.Session is created for each HTTP request so the client remains
    safe under concurrent use without sharing mutable session state between workers.
    """

    def __init__(self, config: FlowGuardConfig | None = None) -> None:
        self.config = config or FlowGuardConfig()

    def _build_url(self, path: str, mode: str | None = None) -> str:
        """Return the fully-qualified endpoint for a mode-specific ShopZone route."""
        if not isinstance(path, str) or not path or any(ord(char) < 32 for char in path):
            raise ValueError("Invalid request path; only local API paths are allowed.")
        try:
            parsed_path = urlsplit(path)
        except ValueError as exc:
            raise ValueError("Invalid request path; only local API paths are allowed.") from exc
        if parsed_path.scheme or parsed_path.netloc or path.startswith(("//", "\\\\")):
            raise ValueError("Invalid request path; only local API paths are allowed.")
        if parsed_path.query or parsed_path.fragment or "?" in path or "#" in path or "\\" in path:
            raise ValueError("Invalid request path; only local API paths are allowed.")
        if re.search(r"%(?![0-9a-fA-F]{2})", path):
            raise ValueError("Invalid request path; only local API paths are allowed.")

        selected_mode = (mode or self.config.target_mode).lower()
        if selected_mode not in {"vulnerable", "secure"}:
            raise ValueError("mode must be either 'vulnerable' or 'secure'.")
        if not path.startswith("/"):
            path = f"/{path}"
        decoded_path = path
        for _ in range(8):
            if re.search(r"%(?![0-9a-fA-F]{2})", decoded_path):
                raise ValueError("Invalid request path; only local API paths are allowed.")
            if "%2f" in decoded_path.lower() or "%5c" in decoded_path.lower():
                raise ValueError("Invalid request path; only local API paths are allowed.")
            next_path = unquote(decoded_path)
            if (
                next_path.startswith("//")
                or "\\" in next_path
                or any(segment in {".", ".."} for segment in next_path.split("/"))
            ):
                raise ValueError("Invalid request path; only local API paths are allowed.")
            if next_path == decoded_path:
                break
            decoded_path = next_path
        else:
            raise ValueError("Invalid request path; only local API paths are allowed.")

        if path == "/api" or path.startswith("/api/") or path == "/admin" or path.startswith("/admin/"):
            endpoint = f"{self.config.base_url}{path}"
        elif any(path == prefix or path.startswith(f"{prefix}/") for prefix in ("/vuln", "/sec", "/vulnerable", "/secure")):
            endpoint = f"{self.config.base_url}{path}"
        else:
            endpoint = f"{self.config.base_url}/{selected_mode}/api{path}"

        parsed_endpoint = urlsplit(endpoint)
        configured_origin = urlsplit(self.config.base_url)
        if (
            parsed_endpoint.scheme != configured_origin.scheme
            or parsed_endpoint.hostname != configured_origin.hostname
            or parsed_endpoint.port != configured_origin.port
            or parsed_endpoint.username is not None
            or parsed_endpoint.password is not None
        ):
            raise ValueError("Request endpoint is outside the configured local target.")
        return endpoint

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        mode: str | None = None,
        timeout: float | None = None,
    ) -> ApiResult:
        """Send an HTTP request with timeout and exception handling."""
        endpoint = self._build_url(path, mode=mode)
        endpoint_path = urlsplit(endpoint).path
        configured_path = urlsplit(self.config.base_url).path.rstrip("/")
        relative_path = endpoint_path[len(configured_path):] if configured_path else endpoint_path
        is_admin_allowed = (
            (method.upper() == "GET" and bool(
                re.fullmatch(
                    r"/api/admin/verify/(?:order|payment)/(?:vulnerable|secure)/\d+"
                    r"|/api/admin/verify/coupon/(?:vulnerable|secure)/[^/]+",
                    relative_path,
                )
            ))
            or (method.upper() == "POST" and bool(
                re.fullmatch(
                    r"/api/admin/coupon/(?:vulnerable|secure)",
                    relative_path,
                )
            ))
        )
        request_headers: dict[str, Any] = {}
        for header_source in (self.config.extra_headers, headers or {}):
            for name, value in header_source.items():
                if name.lower() == "x-admin-key" and not is_admin_allowed:
                    continue
                existing_name = next(
                    (existing for existing in request_headers if existing.lower() == name.lower()),
                    None,
                )
                if existing_name is not None:
                    del request_headers[existing_name]
                request_headers[name] = value

        start = time.perf_counter()
        try:
            with requests.Session() as session:
                session.trust_env = False
                response = session.request(
                    method=method.upper(),
                    url=endpoint,
                    json=json,
                    params=params,
                    headers=request_headers,
                    timeout=timeout if timeout is not None else self.config.timeout,
                    allow_redirects=False,
                )
        except requests.Timeout:
            elapsed = (time.perf_counter() - start) * 1000
            return ApiResult(
                status_code=0,
                ok=False,
                payload={"error": "Request timed out."},
                elapsed_ms=elapsed,
                request_method=method.upper(),
                endpoint=redact_text(endpoint),
                error="Request timed out.",
            )
        except requests.RequestException:
            elapsed = (time.perf_counter() - start) * 1000
            return ApiResult(
                status_code=0,
                ok=False,
                payload={"error": "HTTP request failed."},
                elapsed_ms=elapsed,
                request_method=method.upper(),
                endpoint=redact_text(endpoint),
                error="HTTP request failed.",
            )

        elapsed = (time.perf_counter() - start) * 1000
        payload: Any = None
        error: str | None = None
        try:
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type.lower():
                payload = response.json()
            elif response.text:
                payload = response.text
        except ValueError:
            payload = response.text

        if not (200 <= response.status_code < 300):
            payload = sanitize_value(payload)
            if isinstance(payload, dict):
                error = redact_text(str(payload.get("message") or payload.get("error") or response.reason))
            else:
                error = redact_text(str(payload) or response.reason)

        return ApiResult(
            status_code=response.status_code,
            ok=200 <= response.status_code < 300,
            payload=payload,
            elapsed_ms=elapsed,
            request_method=method.upper(),
            endpoint=redact_text(endpoint),
            error=error,
        )

    def get(self, path: str, *, mode: str | None = None, params: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None) -> ApiResult:
        """Send an HTTP GET request."""
        return self._request("GET", path, params=params, headers=headers, mode=mode, timeout=timeout)

    def post(self, path: str, *, json: dict[str, Any] | None = None, mode: str | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None) -> ApiResult:
        """Send an HTTP POST request."""
        return self._request("POST", path, json=json, headers=headers, mode=mode, timeout=timeout)

    def put(self, path: str, *, json: dict[str, Any] | None = None, mode: str | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None) -> ApiResult:
        """Send an HTTP PUT request."""
        return self._request("PUT", path, json=json, headers=headers, mode=mode, timeout=timeout)

    def delete(self, path: str, *, json: dict[str, Any] | None = None, mode: str | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None) -> ApiResult:
        """Send an HTTP DELETE request."""
        return self._request("DELETE", path, json=json, headers=headers, mode=mode, timeout=timeout)

    def register_user(self, username: str, email: str, password: str, *, mode: str | None = None) -> ApiResult:
        """Register a synthetic user on the target ShopZone mode."""
        return self.post(
            "/auth/register",
            mode=mode,
            json={"username": username, "email": email, "password": password},
        )

    def login_user(self, username: str, password: str, *, mode: str | None = None) -> ApiResult:
        """Authenticate and return the response from ShopZone's login endpoint."""
        return self.post(
            "/auth/login",
            mode=mode,
            json={"username": username, "password": password},
        )

    def get_products(self, *, mode: str | None = None) -> ApiResult:
        """Fetch the canonical catalog."""
        return self.get("/products", mode=mode)

    def get_cart(self, headers: dict[str, str], *, mode: str | None = None) -> ApiResult:
        """Fetch the authenticated user cart."""
        return self.get("/cart", mode=mode, headers=headers)

    def add_to_cart(self, headers: dict[str, str], product_id: int, quantity: int = 1, *, mode: str | None = None) -> ApiResult:
        """Add a product to the authenticated user's cart."""
        return self.post("/cart/items", mode=mode, headers=headers, json={"product_id": product_id, "quantity": quantity})

    def update_cart_item(self, headers: dict[str, str], item_id: int, quantity: int, *, mode: str | None = None) -> ApiResult:
        """Update the quantity of a cart item."""
        return self.put(f"/cart/items/{item_id}", mode=mode, headers=headers, json={"quantity": quantity})

    def delete_cart_item(self, headers: dict[str, str], item_id: int, *, mode: str | None = None) -> ApiResult:
        """Delete a cart item by id."""
        return self.delete(f"/cart/items/{item_id}", mode=mode, headers=headers)

    def clear_cart(self, headers: dict[str, str], *, mode: str | None = None) -> ApiResult:
        """Clear the current cart."""
        return self.delete("/cart", mode=mode, headers=headers)

    def checkout(self, headers: dict[str, str], *, mode: str | None = None, **payload: Any) -> ApiResult:
        """Create an order from the authenticated cart."""
        return self.post("/orders/checkout", mode=mode, headers=headers, json=payload)

    def process_payment(self, headers: dict[str, str], order_id: int, *, mode: str | None = None) -> ApiResult:
        """Process a dummy payment for an order."""
        return self.post("/payment/process", mode=mode, headers=headers, json={"order_id": order_id})

    def confirm_order(self, headers: dict[str, str], order_id: int, *, mode: str | None = None) -> ApiResult:
        """Confirm a paid order."""
        return self.post(f"/orders/{order_id}/confirm", mode=mode, headers=headers)

    def cancel_order(self, headers: dict[str, str], order_id: int, *, mode: str | None = None) -> ApiResult:
        """Cancel an eligible order."""
        return self.post(f"/orders/{order_id}/cancel", mode=mode, headers=headers)

    def get_order(self, headers: dict[str, str], order_id: int, *, mode: str | None = None) -> ApiResult:
        """Retrieve a specific order."""
        return self.get(f"/orders/{order_id}", mode=mode, headers=headers)

    def list_orders(self, headers: dict[str, str], *, mode: str | None = None) -> ApiResult:
        """List current user orders."""
        return self.get("/orders", mode=mode, headers=headers)

    def apply_coupon(self, headers: dict[str, str], code: str, *, mode: str | None = None) -> ApiResult:
        """Apply or validate a coupon code."""
        return self.post("/coupons/apply", mode=mode, headers=headers, json={"code": code})

    def admin_verify_order(self, mode: str, order_id: int) -> ApiResult:
        """Query ShopZone's admin verification endpoint for order ground truth."""
        headers = {"X-Admin-Key": self.config.admin_key} if self.config.admin_key else {}
        return self.get(f"/api/admin/verify/order/{mode}/{order_id}", mode=None, headers=headers)

    def admin_verify_payment(self, mode: str, order_id: int) -> ApiResult:
        """Query ShopZone's admin verification endpoint for payment ground truth."""
        headers = {"X-Admin-Key": self.config.admin_key} if self.config.admin_key else {}
        return self.get(f"/api/admin/verify/payment/{mode}/{order_id}", mode=None, headers=headers)

    def admin_verify_coupon(self, mode: str, code: str) -> ApiResult:
        """Query ShopZone's admin verification endpoint for coupon usage ground truth."""
        headers = {"X-Admin-Key": self.config.admin_key} if self.config.admin_key else {}
        return self.get(f"/api/admin/verify/coupon/{mode}/{code}", mode=None, headers=headers)
