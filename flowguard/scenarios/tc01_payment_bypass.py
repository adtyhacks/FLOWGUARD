"""TC-01: detect confirmation of an unpaid ShopZone order."""

from __future__ import annotations

import uuid
from typing import Any

from ..auth import AuthSession, SyntheticUserManager
from ..client import FlowGuardClient
from ..config import ALLOWED_TARGET_MODES
from ..schemas import ApiResult, ScenarioResult
from .base import ScenarioBase, _TimedAuthClient


class TC01PaymentBypassScenario(ScenarioBase):
    """Attempt unpaid-order confirmation and classify via admin ground truth.

    ShopZone exposes no user or order deletion API. Synthetic users and completed
    orders therefore remain in the lab database; this scenario never resets it.
    Cleanup logs out and attempts to clear only the synthetic user's residual cart.
    Repeated runs can leave synthetic accounts and orders behind.
    """

    scenario_id = "TC-01"
    scenario_name = "Payment Bypass Detection"
    expected_behavior = (
        "An unpaid order must not become CONFIRMED; vulnerable mode demonstrates the bypass, "
        "while secure mode rejects confirmation and preserves the unpaid order state."
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

    def _verify_payment(self, mode: str, order_id: int) -> ApiResult:
        headers = {"X-Admin-Key": self.client.config.admin_key} if self.client.config.admin_key else {}
        return self.client.get(
            f"/api/admin/verify/payment/{mode}/{order_id}",
            headers=headers,
            timeout=self.timeout,
        )

    @staticmethod
    def _valid_order_truth(
        result: ApiResult, order_id: int, expected_user_id: int | None = None
    ) -> tuple[bool, str | None]:
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
        status = order.get("status")
        if not isinstance(status, str) or not status:
            return False, None
        return True, status

    @staticmethod
    def _valid_no_payment_truth(result: ApiResult) -> bool:
        return (
            result.status_code == 404
            and isinstance(result.payload, dict)
            and result.payload.get("found") is False
            and result.payload.get("payment") is None
        )

    @staticmethod
    def _expected_secure_rejection(result: ApiResult) -> bool:
        expected_message = (
            "Cannot confirm order in state 'PENDING_PAYMENT'. "
            "Order must be in PAID state."
        )
        return (
            result.status_code == 400
            and isinstance(result.payload, dict)
            and result.payload.get("error") == "Bad Request"
            and result.payload.get("message") == expected_message
        )

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
        username = manager.generate_username("tc01")
        email = manager.generate_email(username)
        password = manager.generate_password()
        registered_user = None
        session: AuthSession | None = None
        cart_mutation_attempted = False
        checkout_completed = False
        order_id: int | None = None
        final_result: ScenarioResult | None = None
        cleanup_evidence_start = 0

        try:
            registered_user = manager.register_user(
                username,
                email,
                password,
                mode=selected_mode,
            )
            self._record(
                step="register_synthetic_user",
                endpoint=f"/{selected_mode}/api/auth/register",
                request_method="POST",
                request_payload={"username": username, "email": email, "password": password},
                response_status_code=201 if registered_user is not None else None,
                response_payload={"registered": registered_user is not None},
                observed_state={"registered": registered_user is not None},
            )
            if registered_user is None:
                final_result = self._result("ERROR", "Synthetic user registration failed.", error="Registration did not return a registered synthetic user.")
                return final_result

            session = manager.login_user(registered_user, mode=selected_mode)
            self._record(
                step="authenticate_synthetic_user",
                endpoint=f"/{selected_mode}/api/auth/login",
                request_method="POST",
                request_payload={"username": registered_user.username, "password": registered_user.password},
                response_status_code=session.session_metadata.get("status_code"),
                response_payload=session.to_dict(),
                observed_state={"authenticated": session.authenticated},
            )
            if not session.authenticated:
                final_result = self._result("ERROR", "Synthetic user authentication failed.", error="Login did not produce a verified session.")
                return final_result

            headers = manager.get_auth_headers(registered_user.username, mode=selected_mode)
            if not headers:
                final_result = self._result("ERROR", "Authenticated session headers were unavailable.", error="No verified bearer header was available.")
                return final_result

            products_result = self.client.get("/products", mode=selected_mode, timeout=self.timeout)
            self._record(
                step="load_product_catalog",
                endpoint=products_result.endpoint,
                request_method="GET",
                result=products_result,
            )
            products_payload = products_result.payload
            products = products_payload.get("products") if isinstance(products_payload, dict) else None
            if products_result.status_code != 200 or not isinstance(products, list):
                final_result = self._result("ERROR", "Product catalog response was missing or malformed.", error="Cannot select a valid catalog product.")
                return final_result
            product = next((item for item in products if isinstance(item, dict) and isinstance(item.get("id"), int) and not isinstance(item.get("id"), bool)), None)
            if product is None:
                final_result = self._result("ERROR", "Product catalog contained no valid product IDs.", error="Cannot create cart without a valid product.")
                return final_result
            product_id = product["id"]

            cart_mutation_attempted = True
            cart_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="add_product_to_cart",
                endpoint=cart_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers,
                result=cart_result,
            )
            cart_payload = cart_result.payload
            cart_item = cart_payload.get("cart_item") if isinstance(cart_payload, dict) else None
            if not (200 <= cart_result.status_code < 300) or not isinstance(cart_item, dict):
                final_result = self._result("ERROR", "Cart creation failed or returned malformed data.", error="A validated cart item was not returned.")
                return final_result
            checkout_payload = {"idempotency_key": f"tc01-{uuid.uuid4().hex}"}
            checkout_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json=checkout_payload,
                timeout=self.timeout,
            )
            self._record(
                step="checkout_without_payment",
                endpoint=checkout_result.endpoint,
                request_method="POST",
                request_payload=checkout_payload,
                request_headers=headers,
                result=checkout_result,
            )
            checkout_body = checkout_result.payload
            order = checkout_body.get("order") if isinstance(checkout_body, dict) else None
            candidate_id = order.get("id") if isinstance(order, dict) else None
            if (
                not (200 <= checkout_result.status_code < 300)
                or not isinstance(candidate_id, int)
                or isinstance(candidate_id, bool)
                or not isinstance(order, dict)
                or order.get("status") != "PENDING_PAYMENT"
            ):
                final_result = self._result("ERROR", "Checkout failed or returned a malformed pending order.", error="Cannot safely attempt TC-01 confirmation.")
                return final_result

            order_user_id = order.get("user_id")
            user_id = registered_user.user_id if registered_user is not None else None
            if (
                not isinstance(user_id, int)
                or isinstance(user_id, bool)
                or not isinstance(order_user_id, int)
                or isinstance(order_user_id, bool)
                or order_user_id != user_id
            ):
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Checkout order ownership could not be verified.",
                    error="Order ownership could not be verified: checkout returned an order whose user_id is missing, malformed, or does not match the authenticated synthetic user.",
                )
                return final_result

            order_id = candidate_id
            checkout_completed = True

            confirm_result = self.client.post(
                f"/orders/{order_id}/confirm",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_confirmation_without_payment",
                endpoint=confirm_result.endpoint,
                request_method="POST",
                request_headers=headers,
                result=confirm_result,
                observed_state={"http_success": confirm_result.ok},
            )

            order_truth = self._verify_order(selected_mode, order_id)
            self._record(
                step="verify_order_ground_truth",
                endpoint=order_truth.endpoint,
                request_method="GET",
                result=order_truth,
            )
            order_valid, verified_status = self._valid_order_truth(order_truth, order_id, user_id)

            payment_truth = self._verify_payment(selected_mode, order_id)
            self._record(
                step="verify_payment_ground_truth",
                endpoint=payment_truth.endpoint,
                request_method="GET",
                result=payment_truth,
            )
            no_payment = self._valid_no_payment_truth(payment_truth)

            if not order_valid or not no_payment:
                actual = "Admin verification did not provide complete order and unpaid-payment evidence."
                final_result = self._result("INCONCLUSIVE", actual, error="Ground-truth verification was missing or malformed.")
            elif verified_status == "CONFIRMED":
                final_result = self._result(
                    "FAIL",
                    "Admin verification confirms an unpaid order reached CONFIRMED.",
                )
            elif verified_status != "PENDING_PAYMENT":
                final_result = self._result(
                    "INCONCLUSIVE",
                    f"Admin verification returned unexpected order state '{verified_status}'.",
                    error="Order state contradicts the expected unpaid checkout state.",
                )
            elif selected_mode == "secure" and self._expected_secure_rejection(confirm_result):
                final_result = self._result(
                    "PASS",
                    "Secure mode returned the expected unpaid-order rejection; admin state remains PENDING_PAYMENT with no payment record.",
                )
            elif selected_mode == "secure" and confirm_result.status_code == 0:
                final_result = self._result(
                    "ERROR",
                    "Confirmation request failed before a business rejection could be verified.",
                    error="Confirmation timed out or failed at the transport layer.",
                )
            elif selected_mode == "secure":
                final_result = self._result(
                    "ERROR",
                    f"Secure confirmation returned unexpected HTTP {confirm_result.status_code}; the expected business rejection was not observed.",
                    error="Unexpected confirmation response; not classified as a security PASS.",
                )
            elif selected_mode == "vulnerable" and verified_status == "PENDING_PAYMENT":
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Vulnerable mode did not confirm the unpaid order; no bypass was demonstrated.",
                )
            else:
                final_result = self._result(
                    "INCONCLUSIVE",
                    f"Observed order state '{verified_status}' does not establish the expected TC-01 outcome.",
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
            if cart_mutation_attempted and not checkout_completed and session is not None and registered_user is not None:
                try:
                    residual_headers = manager.get_auth_headers(registered_user.username, mode=selected_mode)
                    if residual_headers:
                        clear_result = self.client.delete("/cart", mode=selected_mode, headers=residual_headers, timeout=self.timeout)
                        self._record(
                            step="cleanup_residual_cart",
                            endpoint=clear_result.endpoint,
                            request_method="DELETE",
                            request_headers=residual_headers,
                            result=clear_result,
                        )
                except Exception:
                    self._record(
                        step="cleanup_cart_error",
                        endpoint=f"/{selected_mode}/api/cart",
                        request_method="DELETE",
                        error="Residual cart cleanup failed.",
                    )

            if session is not None and session.authenticated and registered_user is not None:
                try:
                    logout_headers = dict(session.authentication_headers)
                    logout_result = manager.logout_user(registered_user, mode=selected_mode)
                    self._record(
                        step="cleanup_logout",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        request_headers=logout_headers,
                        response_payload={"server_invalidation_confirmed": logout_result},
                        observed_state={"local_session_cleared": not bool(manager.get_auth_headers(registered_user.username, mode=selected_mode))},
                    )
                except Exception:
                    self._record(
                        step="cleanup_logout_error",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        error="Synthetic user logout cleanup failed.",
                    )
            if final_result is not None:
                final_result.evidence.extend(self._evidence[cleanup_evidence_start:])
