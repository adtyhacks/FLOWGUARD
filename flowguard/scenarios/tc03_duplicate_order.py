"""TC-03: detect duplicate order creation and verify checkout idempotency."""

from __future__ import annotations

import uuid
from typing import Any

from ..auth import AuthSession, SyntheticUserManager
from ..client import FlowGuardClient
from ..config import ALLOWED_TARGET_MODES
from ..schemas import ApiResult, ScenarioResult
from .base import ScenarioBase, _TimedAuthClient


class TC03DuplicateOrderScenario(ScenarioBase):
    """Attempt duplicate checkout replay with the same idempotency key and conflicting payloads.

    In secure mode, identical replay must return the existing order without creating
    duplicates, and conflicting payload reuse must be rejected with HTTP 409 Conflict.
    In vulnerable mode, duplicate orders are created using the same idempotency key.

    ShopZone exposes no order deletion API. Synthetic users and completed orders
    therefore remain in the lab database; this scenario never resets it.
    Cleanup clears only the synthetic user's residual cart and logs out.
    """

    scenario_id = "TC-03"
    scenario_name = "Duplicate Order Creation / Checkout Idempotency"
    expected_behavior = (
        "Checkout with an idempotency key must be idempotent; identical replays must return "
        "the existing order without creating duplicate orders, and conflicting payload reuse "
        "must be rejected with HTTP 409. Vulnerable mode demonstrates duplicate order creation."
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
            or not isinstance(order.get("id"), int)
            or isinstance(order.get("id"), bool)
            or order.get("id") != order_id
        ):
            return False, None
        order_user_id = order.get("user_id")
        if not isinstance(order_user_id, int) or isinstance(order_user_id, bool):
            return False, None
        if expected_user_id is not None:
            if (
                not isinstance(expected_user_id, int)
                or isinstance(expected_user_id, bool)
                or order_user_id != expected_user_id
            ):
                return False, None
        return True, order

    @staticmethod
    def _expected_conflict_rejection(result: ApiResult) -> bool:
        if result.status_code != 409 or not isinstance(result.payload, dict):
            return False
        if result.payload.get("error") != "Conflict":
            return False
        msg = str(result.payload.get("message", "")).lower()
        return "idempotency key" in msg or "mismatched" in msg or "differing payload" in msg

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

        registered_user = None
        session: AuthSession | None = None
        cart_mutated = False
        final_result: ScenarioResult | None = None
        cleanup_evidence_start = 0

        try:
            # -------------------------------------------------------------
            # 1. Register & Authenticate Synthetic User
            # -------------------------------------------------------------
            username = manager.generate_username("tc03")
            email = manager.generate_email(username)
            password = manager.generate_password()

            registered_user = manager.register_user(
                username,
                email,
                password,
                mode=selected_mode,
            )
            if registered_user is None:
                final_result = self._result("ERROR", "Registration failed.", error="HTTP registration failed.")
                return final_result

            user_id = registered_user.user_id
            if not isinstance(user_id, int) or isinstance(user_id, bool):
                final_result = self._result("ERROR", "Registered user has malformed identity.", error="user_id must be integer.")
                return final_result

            session = manager.login_user(registered_user, mode=selected_mode)
            if not session.authenticated:
                final_result = self._result("ERROR", "Authentication failed.", error=session.session_metadata.get("error"))
                return final_result

            headers = manager.get_auth_headers(registered_user.username, mode=selected_mode)

            # -------------------------------------------------------------
            # 2. Retrieve Product Catalog & Select Valid Product
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
            if not isinstance(product_id, int) or isinstance(product_id, bool):
                final_result = self._result("ERROR", "Product catalog was empty or invalid.", error="No valid product ID available.")
                return final_result

            # -------------------------------------------------------------
            # 3. Add Item to Cart for Initial Checkout
            # -------------------------------------------------------------
            cart_result1 = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="add_initial_cart_item",
                endpoint=cart_result1.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers,
                result=cart_result1,
            )
            cart_payload1 = cart_result1.payload
            cart_item1 = cart_payload1.get("cart_item") if isinstance(cart_payload1, dict) else None
            if not (200 <= cart_result1.status_code < 300) or not isinstance(cart_item1, dict):
                final_result = self._result("ERROR", "Cart creation failed.", error="A validated cart item was not returned.")
                return final_result
            cart_mutated = True

            # -------------------------------------------------------------
            # 4. Initial Checkout with Idempotency Key
            # -------------------------------------------------------------
            idempotency_key = f"tc03-{uuid.uuid4().hex}"
            initial_payload = {"idempotency_key": idempotency_key}

            checkout1_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json=initial_payload,
                timeout=self.timeout,
            )
            self._record(
                step="initial_checkout",
                endpoint=checkout1_result.endpoint,
                request_method="POST",
                request_payload=initial_payload,
                request_headers=headers,
                result=checkout1_result,
            )

            checkout1_body = checkout1_result.payload
            order1 = checkout1_body.get("order") if isinstance(checkout1_body, dict) else None
            order1_id = order1.get("id") if isinstance(order1, dict) else None
            order1_user_id = order1.get("user_id") if isinstance(order1, dict) else None
            if (
                checkout1_result.status_code != 201
                or not isinstance(order1, dict)
                or not isinstance(order1_id, int)
                or isinstance(order1_id, bool)
                or not isinstance(order1_user_id, int)
                or isinstance(order1_user_id, bool)
                or order1_user_id != user_id
                or order1.get("status") != "PENDING_PAYMENT"
            ):
                final_result = self._result(
                    "ERROR",
                    "Initial checkout failed or returned malformed order.",
                    error=f"Expected 201 Created, got HTTP {checkout1_result.status_code}.",
                )
                return final_result

            # Initial checkout empties cart in ShopZone
            cart_mutated = False

            # Verify order 1 via ground truth
            truth1 = self._verify_order(selected_mode, order1_id)
            self._record(
                step="verify_initial_order_ground_truth",
                endpoint=truth1.endpoint,
                request_method="GET",
                result=truth1,
            )
            valid1, verified_order1 = self._valid_order_truth(truth1, order1_id, user_id)
            if not valid1 or verified_order1 is None or verified_order1.get("idempotency_key") != idempotency_key:
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Initial order ground truth could not be validated.",
                    error="Admin order verification failed for initial order.",
                )
                return final_result

            # -------------------------------------------------------------
            # 5. Re-populate Cart for Replay / Duplicate Attempt
            # -------------------------------------------------------------
            cart_result2 = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="repopulate_cart_for_replay",
                endpoint=cart_result2.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers,
                result=cart_result2,
            )
            cart_payload2 = cart_result2.payload
            cart_item2 = cart_payload2.get("cart_item") if isinstance(cart_payload2, dict) else None
            if not (200 <= cart_result2.status_code < 300) or not isinstance(cart_item2, dict):
                final_result = self._result("ERROR", "Re-populating cart failed.", error="Cannot setup cart for replay attempt.")
                return final_result
            cart_mutated = True

            # -------------------------------------------------------------
            # 6. Attempt Identical Replay with Same Idempotency Key
            # -------------------------------------------------------------
            replay_payload = {"idempotency_key": idempotency_key}
            checkout2_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json=replay_payload,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_identical_checkout_replay",
                endpoint=checkout2_result.endpoint,
                request_method="POST",
                request_payload=replay_payload,
                request_headers=headers,
                result=checkout2_result,
                observed_state={"http_status": checkout2_result.status_code},
            )

            checkout2_body = checkout2_result.payload
            order2 = checkout2_body.get("order") if isinstance(checkout2_body, dict) else None
            order2_id = order2.get("id") if isinstance(order2, dict) else None
            order2_user_id = order2.get("user_id") if isinstance(order2, dict) else None

            # -------------------------------------------------------------
            # 7. Attempt Conflicting Payload Replay (Mismatched Coupon)
            # -------------------------------------------------------------
            conflict_payload = {
                "idempotency_key": idempotency_key,
                "coupon_code": "CYBERSEC20",
            }
            checkout3_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json=conflict_payload,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_conflicting_payload_replay",
                endpoint=checkout3_result.endpoint,
                request_method="POST",
                request_payload=conflict_payload,
                request_headers=headers,
                result=checkout3_result,
                observed_state={"http_status": checkout3_result.status_code},
            )

            # -------------------------------------------------------------
            # 8. Ground-Truth Verification (User Orders & Admin State)
            # -------------------------------------------------------------
            user_orders_result = self.client.get(
                "/orders",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="list_user_orders_ground_truth",
                endpoint=user_orders_result.endpoint,
                request_method="GET",
                request_headers=headers,
                result=user_orders_result,
            )

            if user_orders_result.status_code != 200 or not isinstance(user_orders_result.payload, dict):
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Could not retrieve user orders list for ground-truth verification.",
                    error="Orders list endpoint failed or returned malformed payload.",
                )
                return final_result

            user_orders = user_orders_result.payload.get("orders")
            if not isinstance(user_orders, list):
                final_result = self._result(
                    "INCONCLUSIVE",
                    "User orders list was malformed.",
                    error="'orders' field was not a list.",
                )
                return final_result

            matching_key_orders = [
                o for o in user_orders
                if isinstance(o, dict)
                and o.get("idempotency_key") == idempotency_key
                and isinstance(o.get("id"), int)
                and not isinstance(o.get("id"), bool)
                and o.get("user_id") == user_id
            ]

            # -------------------------------------------------------------
            # 9. Mode-Specific Classification
            # -------------------------------------------------------------
            if selected_mode == "vulnerable":
                # In vulnerable mode, replay creates a new distinct order
                if (
                    checkout2_result.status_code == 201
                    and isinstance(order2, dict)
                    and isinstance(order2_id, int)
                    and not isinstance(order2_id, bool)
                    and order2_user_id == user_id
                    and order2_id != order1_id
                ):
                    # Verify second order via admin ground truth
                    truth2 = self._verify_order(selected_mode, order2_id)
                    self._record(
                        step="verify_duplicate_order_ground_truth",
                        endpoint=truth2.endpoint,
                        request_method="GET",
                        result=truth2,
                    )
                    valid2, verified_order2 = self._valid_order_truth(truth2, order2_id, user_id)

                    if valid2 and len(matching_key_orders) >= 2:
                        final_result = self._result(
                            "FAIL",
                            f"Duplicate order creation confirmed: sequential checkout with the same idempotency key "
                            f"created distinct orders #{order1_id} and #{order2_id}.",
                        )
                    else:
                        final_result = self._result(
                            "INCONCLUSIVE",
                            "Vulnerable replay returned 201 but admin/user ground truth contradicted duplicate order creation.",
                            error="Admin verification or user orders count did not corroborate duplicate order.",
                        )
                elif checkout2_result.status_code in (200, 409):
                    final_result = self._result(
                        "INCONCLUSIVE",
                        f"Vulnerable mode did not create duplicate orders; replay returned HTTP {checkout2_result.status_code}.",
                        error="Expected duplicate creation flaw was not observed.",
                    )
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        f"Vulnerable replay returned unexpected HTTP {checkout2_result.status_code}.",
                        error="Unexpected checkout response status.",
                    )

            elif selected_mode == "secure":
                replay_is_idempotent = (
                    checkout2_result.status_code == 200
                    and isinstance(order2, dict)
                    and order2_id == order1_id
                    and checkout2_body.get("idempotent_replay") is True
                )
                conflict_is_rejected = self._expected_conflict_rejection(checkout3_result)
                single_order_in_truth = len(matching_key_orders) == 1 and matching_key_orders[0].get("id") == order1_id

                if replay_is_idempotent and conflict_is_rejected and single_order_in_truth:
                    final_result = self._result(
                        "PASS",
                        "Idempotent checkout verified: identical replay returned existing order without creating duplicates, "
                        "conflicting payload was rejected with HTTP 409, and exactly one order exists in ground truth.",
                    )
                elif checkout2_result.status_code == 201 or order2_id != order1_id or len(matching_key_orders) > 1:
                    final_result = self._result(
                        "FAIL",
                        "Secure mode permitted duplicate order creation for the same idempotency key.",
                    )
                elif not conflict_is_rejected:
                    final_result = self._result(
                        "ERROR",
                        f"Secure mode failed to reject conflicting payload with HTTP 409 Conflict (got HTTP {checkout3_result.status_code}).",
                        error="Conflicting idempotency key payload was not properly rejected.",
                    )
                else:
                    final_result = self._result(
                        "ERROR",
                        f"Secure replay returned unexpected HTTP {checkout2_result.status_code}; expected idempotent 200 replay.",
                        error="Idempotent replay contract violation.",
                    )
            else:
                final_result = self._result(
                    "INCONCLUSIVE",
                    f"Unexpected mode evaluation '{selected_mode}'.",
                )

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

            # Cleanup residual cart if still present
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
                    logout_res = manager.logout_user(registered_user, mode=selected_mode)
                    self._record(
                        step="logout_synthetic_user",
                        endpoint=logout_res.endpoint,
                        request_method="POST",
                        request_headers=logout_headers,
                        result=logout_res,
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
