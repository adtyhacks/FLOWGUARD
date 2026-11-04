"""TC-04: Order IDOR (Insecure Direct Object Reference) assessment scenario."""

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


class TC04OrderIDORScenario(ScenarioBase):
    """Test object-level authorization and detect Insecure Direct Object References on orders.

    In secure mode, querying an order with another user's credentials must be denied
    (returning HTTP 404 or 403) without disclosing any order details, while the legitimate
    owner retains access to view their order.
    In vulnerable mode, any authenticated user can view any other user's order details
    simply by referencing the order ID.

    ShopZone exposes no order deletion API. Synthetic users and completed orders
    therefore remain in the lab database; this scenario never resets it.
    Cleanup clears only the synthetic users' residual carts and logs out both sessions.
    """

    scenario_id = "TC-04"
    scenario_name = "Order IDOR / Unauthorized Cross-User Access"
    expected_behavior = (
        "Authenticated users must only be able to view their own orders. Accessing another user's "
        "order must be denied without disclosing order details, while the resource owner retains access. "
        "Vulnerable mode demonstrates unauthorized order disclosure (IDOR)."
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

    @staticmethod
    def _valid_order_payload(
        payload: Any, order_id: int, expected_user_id: int | None = None
    ) -> tuple[bool, dict[str, Any] | None]:
        if not isinstance(payload, dict):
            return False, None
        order = payload.get("order")
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

    def run(self, mode: str) -> ScenarioResult:
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

        manager = SyntheticUserManager(
            client=_TimedAuthClient(self.client, self.timeout),
            mode=selected_mode,
        )

        registered_user_a = None
        session_a: AuthSession | None = None
        cart_a_mutated = False
        checkout_a_completed = False

        registered_user_b = None
        session_b: AuthSession | None = None
        cart_b_mutated = False

        final_result: ScenarioResult | None = None
        cleanup_evidence_start = 0

        try:
            # -------------------------------------------------------------
            # Step 1: User A (victim) registration and login
            # -------------------------------------------------------------
            username_a = manager.generate_username("tc04_victim")
            email_a = manager.generate_email(username_a)
            password_a = manager.generate_password()

            registered_user_a = manager.register_user(username_a, email_a, password_a, mode=selected_mode)
            if registered_user_a is None:
                final_result = self._result("ERROR", "Registration failed for user A.", error="HTTP registration failed.")
                return final_result

            user_a_id = registered_user_a.user_id
            if not _validate_positive_int_id(user_a_id):
                final_result = self._result("ERROR", "User A identity is malformed.", error="user_id must be a positive integer.")
                return final_result

            session_a = manager.login_user(registered_user_a, mode=selected_mode)
            if not session_a.authenticated:
                final_result = self._result("ERROR", "Authentication failed for user A.", error=session_a.session_metadata.get("error"))
                return final_result

            headers_a = manager.get_auth_headers(registered_user_a.username, mode=selected_mode)

            # -------------------------------------------------------------
            # Step 2: Fetch product catalog and populate User A's cart
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
            product_id = products[0].get("id") if (isinstance(products, list) and products and isinstance(products[0], dict)) else None
            if not _validate_positive_int_id(product_id):
                final_result = self._result("ERROR", "Product catalog was empty or invalid.", error="No valid product ID available.")
                return final_result

            cart_a_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers_a,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="add_product_to_cart_user_a",
                endpoint=cart_a_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers_a,
                result=cart_a_result,
            )
            cart_a_payload = cart_a_result.payload
            cart_a_item = cart_a_payload.get("cart_item") if isinstance(cart_a_payload, dict) else None
            if not (200 <= cart_a_result.status_code < 300) or not isinstance(cart_a_item, dict):
                final_result = self._result("ERROR", "Cart creation failed for user A.", error="A validated cart item was not returned.")
                return final_result
            cart_a_mutated = True

            # -------------------------------------------------------------
            # Step 3: User A completes checkout
            # -------------------------------------------------------------
            checkout_idempotency_key = f"tc04-{uuid.uuid4().hex}"
            checkout_payload = {"idempotency_key": checkout_idempotency_key}
            checkout_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers_a,
                json=checkout_payload,
                timeout=self.timeout,
            )
            self._record(
                step="checkout_user_a",
                endpoint=checkout_result.endpoint,
                request_method="POST",
                request_payload=checkout_payload,
                request_headers=headers_a,
                result=checkout_result,
            )
            if checkout_result.status_code != 201 or not isinstance(checkout_result.payload, dict):
                final_result = self._result(
                    "ERROR",
                    f"Checkout failed for user A with HTTP {checkout_result.status_code}.",
                    error="Checkout endpoint failed to create order.",
                )
                return final_result

            order_a = checkout_result.payload.get("order")
            order_id = order_a.get("id") if isinstance(order_a, dict) else None
            if not _validate_positive_int_id(order_id):
                final_result = self._result("ERROR", "Checkout response returned invalid order ID.", error="order.id must be a positive integer.")
                return final_result
            checkout_a_completed = True

            # -------------------------------------------------------------
            # Step 4: Authoritative admin verification of User A's order
            # -------------------------------------------------------------
            truth_result = self._verify_order(selected_mode, order_id)
            self._record(
                step="verify_order_ground_truth_initial",
                endpoint=truth_result.endpoint,
                request_method="GET",
                result=truth_result,
            )
            if truth_result.status_code in (401, 403):
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Admin verification rejected credentials; cannot inspect order ground truth.",
                    error="ADMIN_KEY was invalid or rejected by admin endpoint.",
                )
                return final_result

            if truth_result.status_code == 404:
                final_result = self._result(
                    "INCONCLUSIVE",
                    f"Order {order_id} not found in admin ground truth.",
                    error="Created order was not found in admin verification.",
                )
                return final_result

            valid_truth, verified_order = self._valid_order_truth(truth_result, order_id, expected_user_id=user_a_id)
            if not valid_truth or verified_order is None:
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Admin verification returned invalid or mismatched order state.",
                    error="Initial ground-truth verification was malformed or user mismatch occurred.",
                )
                return final_result

            if verified_order.get("status") != "PENDING_PAYMENT":
                final_result = self._result(
                    "INCONCLUSIVE",
                    f"Admin verification returned unexpected order state '{verified_order.get('status')}'.",
                    error="Expected initial order status to be PENDING_PAYMENT.",
                )
                return final_result

            # -------------------------------------------------------------
            # Step 5: User B (attacker) registration and login
            # -------------------------------------------------------------
            username_b = manager.generate_username("tc04_attacker")
            email_b = manager.generate_email(username_b)
            password_b = manager.generate_password()

            registered_user_b = manager.register_user(username_b, email_b, password_b, mode=selected_mode)
            if registered_user_b is None:
                final_result = self._result("ERROR", "Registration failed for user B.", error="HTTP registration failed.")
                return final_result

            user_b_id = registered_user_b.user_id
            if not _validate_positive_int_id(user_b_id):
                final_result = self._result("ERROR", "User B identity is malformed.", error="user_id must be a positive integer.")
                return final_result

            if user_b_id == user_a_id:
                final_result = self._result("ERROR", "Synthetic user identities collided.", error="User A and User B must have distinct user IDs.")
                return final_result

            session_b = manager.login_user(registered_user_b, mode=selected_mode)
            if not session_b.authenticated:
                final_result = self._result("ERROR", "Authentication failed for user B.", error=session_b.session_metadata.get("error"))
                return final_result

            headers_b = manager.get_auth_headers(registered_user_b.username, mode=selected_mode)

            # -------------------------------------------------------------
            # Step 6: User B attempts to access User A's order via IDOR
            # -------------------------------------------------------------
            user_b_order_result = self.client.get(
                f"/orders/{order_id}",
                mode=selected_mode,
                headers=headers_b,
                timeout=self.timeout,
            )
            self._record(
                step="user_b_access_user_a_order",
                endpoint=user_b_order_result.endpoint,
                request_method="GET",
                request_headers=headers_b,
                result=user_b_order_result,
            )

            if user_b_order_result.status_code == 0:
                final_result = self._result(
                    "ERROR",
                    "Cross-user order request failed at transport layer.",
                    error=user_b_order_result.error or "Network/timeout failure during IDOR attempt.",
                )
                return final_result

            # -------------------------------------------------------------
            # Step 7: Mode-specific invariant verification and classification
            # -------------------------------------------------------------
            if selected_mode == "vulnerable":
                if user_b_order_result.status_code == 200:
                    valid_leaked_payload, leaked_order = self._valid_order_payload(
                        user_b_order_result.payload, order_id, expected_user_id=user_a_id
                    )
                    if valid_leaked_payload and leaked_order is not None:
                        # Corroborate with admin ground truth that user A owns the order
                        post_truth_result = self._verify_order(selected_mode, order_id)
                        self._record(
                            step="verify_order_ground_truth_post_access",
                            endpoint=post_truth_result.endpoint,
                            request_method="GET",
                            result=post_truth_result,
                        )
                        valid_post_truth, post_order = self._valid_order_truth(
                            post_truth_result, order_id, expected_user_id=user_a_id
                        )
                        if valid_post_truth and post_order is not None:
                            final_result = self._result(
                                "FAIL",
                                "Vulnerable mode permitted unauthorized user B to access victim user A's order details; "
                                "admin verification confirms user A owns the order.",
                            )
                        else:
                            final_result = self._result(
                                "INCONCLUSIVE",
                                "Vulnerable response leaked order data, but admin ground truth contradicted order ownership.",
                                error="Ground truth verification contradicted leaked order ownership.",
                            )
                    else:
                        final_result = self._result(
                            "INCONCLUSIVE",
                            "Vulnerable mode returned HTTP 200, but order payload was malformed or ownership was mismatched.",
                            error="Leaked payload did not contain expected victim order details.",
                        )
                elif user_b_order_result.status_code in (401, 403, 404):
                    final_result = self._result(
                        "INCONCLUSIVE",
                        f"Vulnerable mode denied access to user A's order with HTTP {user_b_order_result.status_code}; "
                        "IDOR vulnerability was not observed.",
                        error="Expected IDOR vulnerability was not demonstrated in vulnerable mode.",
                    )
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        f"Vulnerable mode returned unexpected HTTP {user_b_order_result.status_code} on order access.",
                        error="Unexpected response status.",
                    )

            elif selected_mode == "secure":
                if user_b_order_result.status_code in (403, 404):
                    # Ensure no order details leaked in unauthorized response
                    payload_b = user_b_order_result.payload
                    has_leaked_order = isinstance(payload_b, dict) and "order" in payload_b and isinstance(payload_b["order"], dict)

                    if has_leaked_order:
                        final_result = self._result(
                            "FAIL",
                            f"Secure mode returned HTTP {user_b_order_result.status_code} but leaked order dictionary in response body.",
                            error="Order data was disclosed in an error/denial response body.",
                        )
                        return final_result

                    # Verify legitimate owner (User A) still has full access
                    user_a_order_result = self.client.get(
                        f"/orders/{order_id}",
                        mode=selected_mode,
                        headers=headers_a,
                        timeout=self.timeout,
                    )
                    self._record(
                        step="user_a_verify_own_order_access",
                        endpoint=user_a_order_result.endpoint,
                        request_method="GET",
                        request_headers=headers_a,
                        result=user_a_order_result,
                    )

                    if user_a_order_result.status_code != 200:
                        final_result = self._result(
                            "ERROR",
                            f"Legitimate order owner could not access their own order (HTTP {user_a_order_result.status_code}).",
                            error="Resource owner access verification failed.",
                        )
                        return final_result

                    valid_owner_payload, owner_order = self._valid_order_payload(
                        user_a_order_result.payload, order_id, expected_user_id=user_a_id
                    )
                    if not valid_owner_payload or owner_order is None:
                        final_result = self._result(
                            "ERROR",
                            "Legitimate order owner received malformed order details.",
                            error="Owner order payload validation failed.",
                        )
                        return final_result

                    # Re-verify admin ground truth
                    post_truth_result = self._verify_order(selected_mode, order_id)
                    self._record(
                        step="verify_order_ground_truth_post_access",
                        endpoint=post_truth_result.endpoint,
                        request_method="GET",
                        result=post_truth_result,
                    )
                    valid_post_truth, post_order = self._valid_order_truth(
                        post_truth_result, order_id, expected_user_id=user_a_id
                    )
                    if not valid_post_truth or post_order is None:
                        final_result = self._result(
                            "INCONCLUSIVE",
                            "Admin verification failed after secure access check.",
                            error="Post-access ground truth verification failed.",
                        )
                        return final_result

                    final_result = self._result(
                        "PASS",
                        f"Secure mode enforced object-level authorization: unauthorized access was denied "
                        f"(HTTP {user_b_order_result.status_code}) without disclosing order details, "
                        "and the legitimate owner retained access.",
                    )

                elif user_b_order_result.status_code == 200:
                    valid_leaked_payload, leaked_order = self._valid_order_payload(
                        user_b_order_result.payload, order_id, expected_user_id=user_a_id
                    )
                    if valid_leaked_payload and leaked_order is not None:
                        final_result = self._result(
                            "FAIL",
                            "Secure mode permitted unauthorized user B to access victim user A's order (IDOR vulnerability detected).",
                        )
                    else:
                        final_result = self._result(
                            "FAIL",
                            "Secure mode returned HTTP 200 to unauthorized user B on victim user A's order.",
                        )
                else:
                    final_result = self._result(
                        "ERROR",
                        f"Secure mode returned unexpected HTTP {user_b_order_result.status_code} on unauthorized order access.",
                        error="Unexpected response status code.",
                    )

            else:
                final_result = self._result("INCONCLUSIVE", f"Unexpected mode evaluation '{selected_mode}'.")

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

            # Cleanup residual cart for User A if still present
            if cart_a_mutated and not checkout_a_completed and session_a is not None and registered_user_a is not None:
                try:
                    res_headers_a = manager.get_auth_headers(registered_user_a.username, mode=selected_mode)
                    if res_headers_a:
                        clear_res_a = self.client.delete("/cart", mode=selected_mode, headers=res_headers_a, timeout=self.timeout)
                        self._record(
                            step="cleanup_residual_cart_user_a",
                            endpoint=clear_res_a.endpoint,
                            request_method="DELETE",
                            request_headers=res_headers_a,
                            result=clear_res_a,
                        )
                except Exception:
                    self._record(
                        step="cleanup_cart_error_user_a",
                        endpoint=f"/{selected_mode}/api/cart",
                        request_method="DELETE",
                        error="Residual cart cleanup failed for user A.",
                    )

            # Cleanup residual cart for User B if ever mutated
            if cart_b_mutated and session_b is not None and registered_user_b is not None:
                try:
                    res_headers_b = manager.get_auth_headers(registered_user_b.username, mode=selected_mode)
                    if res_headers_b:
                        clear_res_b = self.client.delete("/cart", mode=selected_mode, headers=res_headers_b, timeout=self.timeout)
                        self._record(
                            step="cleanup_residual_cart_user_b",
                            endpoint=clear_res_b.endpoint,
                            request_method="DELETE",
                            request_headers=res_headers_b,
                            result=clear_res_b,
                        )
                except Exception:
                    self._record(
                        step="cleanup_cart_error_user_b",
                        endpoint=f"/{selected_mode}/api/cart",
                        request_method="DELETE",
                        error="Residual cart cleanup failed for user B.",
                    )

            # Logout synthetic user A
            if session_a is not None and session_a.authenticated and registered_user_a is not None:
                try:
                    logout_headers_a = dict(session_a.authentication_headers)
                    logout_res_a = manager.logout_user(registered_user_a, mode=selected_mode)
                    self._record(
                        step="logout_synthetic_user_a",
                        endpoint=logout_res_a.endpoint,
                        request_method="POST",
                        request_headers=logout_headers_a,
                        result=logout_res_a,
                    )
                except Exception:
                    self._record(
                        step="logout_synthetic_user_a_error",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        error="Synthetic user A logout failed.",
                    )

            # Logout synthetic user B
            if session_b is not None and session_b.authenticated and registered_user_b is not None:
                try:
                    logout_headers_b = dict(session_b.authentication_headers)
                    logout_res_b = manager.logout_user(registered_user_b, mode=selected_mode)
                    self._record(
                        step="logout_synthetic_user_b",
                        endpoint=logout_res_b.endpoint,
                        request_method="POST",
                        request_headers=logout_headers_b,
                        result=logout_res_b,
                    )
                except Exception:
                    self._record(
                        step="logout_synthetic_user_b_error",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        error="Synthetic user B logout failed.",
                    )

            if final_result is not None and cleanup_evidence_start < len(self._evidence):
                final_result.evidence.extend(self._evidence[cleanup_evidence_start:])
