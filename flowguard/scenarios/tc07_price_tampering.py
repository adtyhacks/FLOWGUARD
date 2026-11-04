"""TC-07: Client-Side Price Tampering scenario."""

from __future__ import annotations

import uuid
from typing import Any

from ..auth import AuthSession, SyntheticUserManager
from ..client import FlowGuardClient
from ..config import ALLOWED_TARGET_MODES
from ..schemas import ApiResult, ScenarioResult
from .base import ScenarioBase, _TimedAuthClient


def _validate_positive_int_id(val: Any) -> bool:
    """Strictly validate that an ID is a positive integer and not a boolean."""
    if val is None or isinstance(val, bool):
        return False
    return isinstance(val, int) and val > 0


class TC07PriceTamperingScenario(ScenarioBase):
    """Test client-side price tampering and verify server-authoritative pricing.

    In secure mode, checkout must enforce server-authoritative pricing based on catalog
    product unit prices and cart quantities, completely ignoring or rejecting any
    client-supplied total_amount.
    In vulnerable mode, checkout blindly accepts client-submitted total_amount, allowing
    attackers to purchase products at arbitrary manipulated prices.

    ShopZone exposes no order deletion API. Synthetic users and completed orders
    therefore remain in the lab database; this scenario never resets it.
    Cleanup clears only the synthetic user's residual cart and logs out the session.
    """

    scenario_id = "TC-07"
    scenario_name = "Client-Side Price Tampering / Server-Authoritative Pricing"
    expected_behavior = (
        "Checkout must enforce server-authoritative pricing based on catalog product unit "
        "prices and quantities, ignoring or rejecting any client-supplied total_amount. "
        "Vulnerable mode demonstrates price tampering vulnerabilities by accepting client-supplied totals."
    )

    def __init__(
        self,
        client: FlowGuardClient | None = None,
        *,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(client, timeout=timeout)

    def _verify_order(self, mode: str, order_id: int) -> ApiResult:
        headers = {"X-Admin-Key": self.client.config.admin_key} if self.client.config.admin_key else {}
        return self.client.get(
            f"/api/admin/verify/order/{mode}/{order_id}",
            headers=headers,
            timeout=self.timeout,
        )

    @staticmethod
    def _valid_order_truth(
        result: ApiResult, order_id: int, expected_user_id: int | None = None
    ) -> tuple[bool, dict[str, Any] | None]:
        if result.status_code != 200 or not isinstance(result.payload, dict):
            return False, None
        if result.payload.get("found") is not True:
            return False, None
        order = result.payload.get("order")
        if (
            not isinstance(order, dict)
            or not _validate_positive_int_id(order.get("id"))
            or order.get("id") != order_id
        ):
            return False, None
        order_user_id = order.get("user_id")
        if not _validate_positive_int_id(order_user_id):
            return False, None
        if expected_user_id is not None:
            if not _validate_positive_int_id(expected_user_id) or order_user_id != expected_user_id:
                return False, None
        return True, order

    def run(self, mode: str, tampered_amount: int = 100) -> ScenarioResult:
        self._begin()
        selected_mode = str(mode).lower()
        if selected_mode not in ALLOWED_TARGET_MODES:
            return self._result("ERROR", "Invalid ShopZone mode.", error="mode must be vulnerable or secure.")

        if not self.client.config.admin_key:
            return self._result(
                "INCONCLUSIVE",
                "Admin verification is not configured; no scenario requests were made.",
                error="ADMIN_KEY is required for independent ground-truth verification.",
            )

        if not isinstance(tampered_amount, int) or isinstance(tampered_amount, bool) or tampered_amount < 0:
            return self._result(
                "ERROR",
                "Invalid tampered amount.",
                error="tampered_amount must be a non-negative integer.",
            )

        manager = SyntheticUserManager(
            client=_TimedAuthClient(self.client, self.timeout),
            mode=selected_mode,
        )

        registered_user = None
        session: AuthSession | None = None
        cart_mutated = False

        final_result: ScenarioResult | None = None
        cleanup_evidence_start = 0

        try:
            # -------------------------------------------------------------
            # Step 1: Synthetic user registration and authentication
            # -------------------------------------------------------------
            username = manager.generate_username("tc07_tamperer")
            email = manager.generate_email(username)
            password = manager.generate_password()

            registered_user = manager.register_user(username, email, password, mode=selected_mode)
            if registered_user is None:
                final_result = self._result("ERROR", "Registration failed for synthetic user.", error="HTTP registration failed.")
                return final_result

            user_id = registered_user.user_id
            if not _validate_positive_int_id(user_id):
                final_result = self._result("ERROR", "Synthetic user identity is malformed.", error="user_id must be a positive integer.")
                return final_result

            session = manager.login_user(registered_user, mode=selected_mode)
            if not session.authenticated:
                final_result = self._result("ERROR", "Authentication failed for synthetic user.", error=session.session_metadata.get("error"))
                return final_result

            headers = manager.get_auth_headers(registered_user.username, mode=selected_mode)

            # -------------------------------------------------------------
            # Step 2: Authoritative Product Catalog Lookup
            # -------------------------------------------------------------
            catalog_result = self.client.get("/products", mode=selected_mode, timeout=self.timeout)
            self._record(
                step="fetch_product_catalog",
                endpoint=catalog_result.endpoint,
                request_method="GET",
                result=catalog_result,
            )
            if catalog_result.status_code != 200 or not isinstance(catalog_result.payload, dict):
                final_result = self._result("ERROR", "Product catalog could not be retrieved.", error="Catalog endpoint failed.")
                return final_result

            products = catalog_result.payload.get("products")
            if not isinstance(products, list) or not products:
                final_result = self._result("ERROR", "Product catalog was empty or invalid.", error="No products available.")
                return final_result

            product = products[0]
            if not isinstance(product, dict):
                final_result = self._result("ERROR", "Product catalog entry is malformed.", error="Invalid product dict.")
                return final_result

            product_id = product.get("id")
            unit_price = product.get("price_minor_units")
            if not _validate_positive_int_id(product_id) or not isinstance(unit_price, int) or isinstance(unit_price, bool) or unit_price <= 0:
                final_result = self._result("ERROR", "Product pricing or ID is invalid.", error="Invalid product price or ID.")
                return final_result

            quantity = 1
            expected_total = unit_price * quantity

            # Adjust tampered amount if needed so it is strictly less than legitimate price
            target_tampered = tampered_amount
            if target_tampered >= expected_total:
                target_tampered = expected_total // 2

            # -------------------------------------------------------------
            # Step 3: Populate Cart
            # -------------------------------------------------------------
            cart_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": quantity},
                timeout=self.timeout,
            )
            self._record(
                step="populate_cart",
                endpoint=cart_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": quantity},
                request_headers=headers,
                result=cart_result,
            )
            cart_payload = cart_result.payload
            cart_item = cart_payload.get("cart_item") if isinstance(cart_payload, dict) else None
            if not (200 <= cart_result.status_code < 300) or not isinstance(cart_item, dict):
                final_result = self._result("ERROR", "Cart creation failed.", error="Cart item was not returned.")
                return final_result
            cart_mutated = True

            # -------------------------------------------------------------
            # Step 4: Submit Checkout with Manipulated Price
            # -------------------------------------------------------------
            idempotency_key = f"tc07-tamper-{uuid.uuid4().hex}"
            tamper_payload = {
                "idempotency_key": idempotency_key,
                "total_amount": target_tampered,
            }

            checkout_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json=tamper_payload,
                timeout=self.timeout,
            )
            self._record(
                step="submit_tampered_checkout",
                endpoint=checkout_result.endpoint,
                request_method="POST",
                request_payload=tamper_payload,
                request_headers=headers,
                result=checkout_result,
            )

            if checkout_result.status_code != 201 or not isinstance(checkout_result.payload, dict):
                final_result = self._result(
                    "ERROR",
                    "Checkout request did not complete normally.",
                    error=f"Unexpected checkout status {checkout_result.status_code}.",
                )
                return final_result

            order_data = checkout_result.payload.get("order")
            if not isinstance(order_data, dict):
                final_result = self._result("ERROR", "Checkout response missing order dictionary.", error="Malformed order payload.")
                return final_result

            order_id = order_data.get("id")
            if not _validate_positive_int_id(order_id):
                final_result = self._result("ERROR", "Checkout response returned invalid order ID.", error="order_id must be a positive integer.")
                return final_result

            # -------------------------------------------------------------
            # Step 5: Authoritative Ground Truth Verification
            # -------------------------------------------------------------
            admin_truth = self._verify_order(selected_mode, order_id)
            self._record(
                step="admin_verify_tampered_order",
                endpoint=admin_truth.endpoint,
                request_method="GET",
                request_headers={"X-Admin-Key": self.client.config.admin_key},
                result=admin_truth,
            )

            valid_truth, ground_order = self._valid_order_truth(admin_truth, order_id, expected_user_id=user_id)
            if not valid_truth or ground_order is None:
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Admin ground-truth verification for tampered order failed or mismatched user ownership.",
                    error="Ground truth verification failed.",
                )
                return final_result

            if ground_order.get("status") != "PENDING_PAYMENT":
                final_result = self._result(
                    "INCONCLUSIVE",
                    f"Unexpected order status '{ground_order.get('status')}' in ground truth.",
                    error="Order state mismatch.",
                )
                return final_result

            stored_total = ground_order.get("total_minor_units")
            if not isinstance(stored_total, int) or isinstance(stored_total, bool) or stored_total < 0:
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Stored order total in ground truth is not a valid integer.",
                    error="total_minor_units is malformed.",
                )
                return final_result

            # -------------------------------------------------------------
            # Step 6: Mode-Specific Classification
            # -------------------------------------------------------------
            if selected_mode == "vulnerable":
                if stored_total == target_tampered and target_tampered != expected_total:
                    final_result = self._result(
                        "FAIL",
                        f"Vulnerable mode permitted client-side price tampering: order #{order_id} stored "
                        f"client-submitted total of {stored_total} minor units instead of canonical catalog "
                        f"price {expected_total} minor units.",
                    )
                elif stored_total == expected_total:
                    final_result = self._result(
                        "PASS",
                        f"Vulnerable mode unexpectedly enforced canonical server price of {stored_total} minor units.",
                    )
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        f"Order #{order_id} total {stored_total} matched neither tampered amount ({target_tampered}) "
                        f"nor expected canonical price ({expected_total}).",
                    )
                return final_result

            elif selected_mode == "secure":
                if stored_total == expected_total:
                    final_result = self._result(
                        "PASS",
                        f"Secure mode strictly enforced server-authoritative pricing: order #{order_id} "
                        f"canonical total is {stored_total} minor units (matching catalog unit price {unit_price} x {quantity}), "
                        f"ignoring client-submitted tampered amount of {target_tampered} minor units.",
                    )
                elif stored_total == target_tampered and target_tampered != expected_total:
                    final_result = self._result(
                        "FAIL",
                        f"Secure mode permitted client-side price tampering: order #{order_id} accepted "
                        f"tampered price {stored_total} minor units instead of canonical price {expected_total} minor units.",
                    )
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        f"Order #{order_id} stored total {stored_total} minor units did not match expected canonical total {expected_total}.",
                    )
                return final_result

            else:
                final_result = self._result("INCONCLUSIVE", f"Unexpected mode '{selected_mode}'.")
                return final_result

        except Exception as exc:
            self._record(
                step="scenario_execution_error",
                endpoint="local ShopZone scenario",
                request_method="INTERNAL",
                error=str(exc),
            )
            final_result = self._result("ERROR", "Scenario execution failed.", error="An unexpected local scenario error occurred.")
            return final_result

        finally:
            cleanup_evidence_start = len(self._evidence)

            # Clean residual cart if any items remain
            if cart_mutated and session is not None and registered_user is not None:
                try:
                    res_headers = manager.get_auth_headers(registered_user.username, mode=selected_mode)
                    if res_headers:
                        clear_res = self.client.delete("/cart", mode=selected_mode, headers=res_headers, timeout=self.timeout)
                        self._record(
                            step="cleanup_residual_cart",
                            endpoint=clear_res.endpoint,
                            request_method="DELETE",
                            request_headers=res_headers,
                            result=clear_res,
                        )
                except Exception:
                    self._record(
                        step="cleanup_cart_error",
                        endpoint=f"/{selected_mode}/api/cart",
                        request_method="DELETE",
                        error="Residual cart cleanup failed.",
                    )

            # Logout synthetic user
            if session is not None and session.authenticated and registered_user is not None:
                try:
                    logout_headers = dict(session.authentication_headers)
                    logout_ok = manager.logout_user(registered_user, mode=selected_mode)
                    self._record(
                        step="logout_synthetic_user",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        request_headers=logout_headers,
                        response_payload={"server_invalidation_confirmed": logout_ok},
                        observed_state={"local_session_cleared": not bool(manager.get_auth_headers(registered_user.username, mode=selected_mode))},
                    )
                except Exception:
                    self._record(
                        step="logout_synthetic_user_error",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        error="Synthetic user logout failed.",
                    )

            if final_result is not None and cleanup_evidence_start < len(self._evidence):
                final_result.evidence.extend(self._evidence[cleanup_evidence_start:])
