"""TC-05: Invalid Workflow Transitions / State Machine Enforcement scenario."""

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


class TC05InvalidWorkflowScenario(ScenarioBase):
    """Test finite state machine validation and detect invalid workflow transitions on orders.

    In secure mode, order state transitions must follow a validated finite state machine:
    - PENDING_PAYMENT -> CONFIRMED is rejected (unpaid confirmation prevention, HTTP 400)
    - PENDING_PAYMENT -> CANCELLED is allowed (legitimate cancellation)
    - CANCELLED is terminal: CANCELLED -> CANCELLED (repeated cancellation) is rejected (HTTP 400)
    - CANCELLED is terminal: CANCELLED -> CONFIRMED (resurrection) is rejected (HTTP 400)
    - CONFIRMED is terminal: cannot be cancelled or confirmed again

    In vulnerable mode, order routes lack state validation:
    - Any order can be confirmed regardless of payment or state (unpaid confirmation)
    - Repeated confirmations succeed
    - Cancelled orders can be resurrected into CONFIRMED
    - Terminal states accept repeated mutations

    ShopZone exposes no order deletion API. Synthetic users and completed orders
    therefore remain in the lab database; this scenario never resets it.
    Cleanup clears only the synthetic user's residual cart and logs out the session.
    """

    scenario_id = "TC-05"
    scenario_name = "Invalid Workflow Transitions / State Machine Enforcement"
    expected_behavior = (
        "Order state transitions must follow a strict finite state machine. Unpaid orders cannot be "
        "confirmed, terminal states (CANCELLED, CONFIRMED) cannot be mutated or repeated, and "
        "unauthorized transitions must be rejected with HTTP 400 without state alteration. "
        "Vulnerable mode demonstrates state machine bypass and illegal transitions."
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
        status = order.get("status")
        if not isinstance(status, str) or not status:
            return False, None
        return True, order

    @staticmethod
    def _valid_no_payment_truth(result: ApiResult) -> bool:
        return (
            result.status_code == 404
            and isinstance(result.payload, dict)
            and result.payload.get("found") is False
            and result.payload.get("payment") is None
        )

    @staticmethod
    def _expected_confirm_rejection(result: ApiResult, current_state: str) -> bool:
        if result.status_code != 400 or not isinstance(result.payload, dict):
            return False
        if result.payload.get("error") != "Bad Request":
            return False
        msg = str(result.payload.get("message", ""))
        return f"Cannot confirm order in state '{current_state}'" in msg and "PAID" in msg

    @staticmethod
    def _expected_cancel_rejection(result: ApiResult, current_state: str) -> bool:
        if result.status_code != 400 or not isinstance(result.payload, dict):
            return False
        if result.payload.get("error") != "Bad Request":
            return False
        msg = str(result.payload.get("message", ""))
        return f"Cannot cancel order in state '{current_state}'" in msg

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
        checkout1_completed = False
        checkout2_completed = False

        final_result: ScenarioResult | None = None
        cleanup_evidence_start = 0

        try:
            # -------------------------------------------------------------
            # Step 1: Synthetic user registration and authentication
            # -------------------------------------------------------------
            username = manager.generate_username("tc05_fsm")
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
            # Step 2: Fetch product catalog
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

            # -------------------------------------------------------------
            # Step 3: Create Order 1 for Unpaid & Repeated Confirmation testing
            # -------------------------------------------------------------
            cart1_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="add_product_to_cart_order1",
                endpoint=cart1_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers,
                result=cart1_result,
            )
            cart1_payload = cart1_result.payload
            cart1_item = cart1_payload.get("cart_item") if isinstance(cart1_payload, dict) else None
            if not (200 <= cart1_result.status_code < 300) or not isinstance(cart1_item, dict):
                final_result = self._result("ERROR", "Cart creation failed for Order 1.", error="Cart item was not returned.")
                return final_result
            cart_mutated = True

            checkout1_key = f"tc05-ord1-{uuid.uuid4().hex}"
            checkout1_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json={"idempotency_key": checkout1_key},
                timeout=self.timeout,
            )
            self._record(
                step="checkout_order1",
                endpoint=checkout1_result.endpoint,
                request_method="POST",
                request_payload={"idempotency_key": checkout1_key},
                request_headers=headers,
                result=checkout1_result,
            )
            if checkout1_result.status_code != 201 or not isinstance(checkout1_result.payload, dict):
                final_result = self._result("ERROR", "Checkout failed for Order 1.", error="Checkout endpoint failed to create Order 1.")
                return final_result

            order1 = checkout1_result.payload.get("order")
            order1_id = order1.get("id") if isinstance(order1, dict) else None
            if not _validate_positive_int_id(order1_id):
                final_result = self._result("ERROR", "Order 1 returned invalid ID.", error="order.id must be a positive integer.")
                return final_result
            checkout1_completed = True

            # Ground truth verification for Order 1
            truth1_init = self._verify_order(selected_mode, order1_id)
            self._record(
                step="verify_order1_ground_truth_initial",
                endpoint=truth1_init.endpoint,
                request_method="GET",
                result=truth1_init,
            )
            if truth1_init.status_code in (401, 403):
                final_result = self._result("INCONCLUSIVE", "Admin verification rejected credentials.", error="Invalid ADMIN_KEY.")
                return final_result
            valid_truth1_init, ord1_init_dict = self._valid_order_truth(truth1_init, order1_id, expected_user_id=user_id)
            if not valid_truth1_init or ord1_init_dict is None or ord1_init_dict.get("status") != "PENDING_PAYMENT":
                final_result = self._result("INCONCLUSIVE", "Order 1 initial state is invalid in ground truth.", error="Initial order state mismatch.")
                return final_result

            # Verify no payment exists for Order 1
            pay1_init = self._verify_payment(selected_mode, order1_id)
            self._record(
                step="verify_order1_no_payment_initial",
                endpoint=pay1_init.endpoint,
                request_method="GET",
                result=pay1_init,
            )
            if not self._valid_no_payment_truth(pay1_init):
                final_result = self._result("INCONCLUSIVE", "Unexpected payment record found for Order 1.", error="Initial payment verification failed.")
                return final_result

            # -------------------------------------------------------------
            # Step 4: Attempt Invalid Transition 1: Unpaid Confirmation (PENDING_PAYMENT -> CONFIRMED)
            # -------------------------------------------------------------
            confirm1_result = self.client.post(
                f"/orders/{order1_id}/confirm",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_unpaid_confirmation",
                endpoint=confirm1_result.endpoint,
                request_method="POST",
                request_headers=headers,
                result=confirm1_result,
            )
            if confirm1_result.status_code == 0:
                final_result = self._result("ERROR", "Unpaid confirmation request failed at transport layer.", error=confirm1_result.error)
                return final_result

            truth1_post_confirm = self._verify_order(selected_mode, order1_id)
            self._record(
                step="verify_order1_ground_truth_post_unpaid_confirm",
                endpoint=truth1_post_confirm.endpoint,
                request_method="GET",
                result=truth1_post_confirm,
            )
            valid_truth1_post, ord1_post_dict = self._valid_order_truth(truth1_post_confirm, order1_id, expected_user_id=user_id)
            if not valid_truth1_post or ord1_post_dict is None:
                final_result = self._result("INCONCLUSIVE", "Order 1 ground truth invalid after unpaid confirmation attempt.", error="Post-confirm verification failed.")
                return final_result

            # -------------------------------------------------------------
            # Step 5: Attempt Invalid Transition 2: Repeated Confirmation on Order 1
            # -------------------------------------------------------------
            confirm1_repeat_result = self.client.post(
                f"/orders/{order1_id}/confirm",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_repeated_confirmation",
                endpoint=confirm1_repeat_result.endpoint,
                request_method="POST",
                request_headers=headers,
                result=confirm1_repeat_result,
            )
            if confirm1_repeat_result.status_code == 0:
                final_result = self._result("ERROR", "Repeated confirmation request failed at transport layer.", error=confirm1_repeat_result.error)
                return final_result

            # -------------------------------------------------------------
            # Step 6: Create Order 2 for Terminal State Testing (Cancellation & Resurrection)
            # -------------------------------------------------------------
            cart2_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="add_product_to_cart_order2",
                endpoint=cart2_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers,
                result=cart2_result,
            )
            cart2_payload = cart2_result.payload
            cart2_item = cart2_payload.get("cart_item") if isinstance(cart2_payload, dict) else None
            if not (200 <= cart2_result.status_code < 300) or not isinstance(cart2_item, dict):
                final_result = self._result("ERROR", "Cart creation failed for Order 2.", error="Cart item was not returned.")
                return final_result

            checkout2_key = f"tc05-ord2-{uuid.uuid4().hex}"
            checkout2_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers,
                json={"idempotency_key": checkout2_key},
                timeout=self.timeout,
            )
            self._record(
                step="checkout_order2",
                endpoint=checkout2_result.endpoint,
                request_method="POST",
                request_payload={"idempotency_key": checkout2_key},
                request_headers=headers,
                result=checkout2_result,
            )
            if checkout2_result.status_code != 201 or not isinstance(checkout2_result.payload, dict):
                final_result = self._result("ERROR", "Checkout failed for Order 2.", error="Checkout endpoint failed to create Order 2.")
                return final_result

            order2 = checkout2_result.payload.get("order")
            order2_id = order2.get("id") if isinstance(order2, dict) else None
            if not _validate_positive_int_id(order2_id):
                final_result = self._result("ERROR", "Order 2 returned invalid ID.", error="order.id must be a positive integer.")
                return final_result
            checkout2_completed = True

            # Ground truth verification for Order 2
            truth2_init = self._verify_order(selected_mode, order2_id)
            self._record(
                step="verify_order2_ground_truth_initial",
                endpoint=truth2_init.endpoint,
                request_method="GET",
                result=truth2_init,
            )
            valid_truth2_init, ord2_init_dict = self._valid_order_truth(truth2_init, order2_id, expected_user_id=user_id)
            if not valid_truth2_init or ord2_init_dict is None or ord2_init_dict.get("status") != "PENDING_PAYMENT":
                final_result = self._result("INCONCLUSIVE", "Order 2 initial state is invalid in ground truth.", error="Initial order state mismatch.")
                return final_result

            # -------------------------------------------------------------
            # Step 7: Legitimate Order 2 Cancellation (PENDING_PAYMENT -> CANCELLED)
            # -------------------------------------------------------------
            cancel2_result = self.client.post(
                f"/orders/{order2_id}/cancel",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="legitimate_order_cancellation",
                endpoint=cancel2_result.endpoint,
                request_method="POST",
                request_headers=headers,
                result=cancel2_result,
            )
            if cancel2_result.status_code != 200:
                final_result = self._result(
                    "ERROR",
                    f"Legitimate cancellation of pending Order 2 failed with HTTP {cancel2_result.status_code}.",
                    error="Valid order cancellation failed.",
                )
                return final_result

            truth2_post_cancel = self._verify_order(selected_mode, order2_id)
            self._record(
                step="verify_order2_ground_truth_post_cancellation",
                endpoint=truth2_post_cancel.endpoint,
                request_method="GET",
                result=truth2_post_cancel,
            )
            valid_truth2_cancel, ord2_cancel_dict = self._valid_order_truth(truth2_post_cancel, order2_id, expected_user_id=user_id)
            if not valid_truth2_cancel or ord2_cancel_dict is None or ord2_cancel_dict.get("status") != "CANCELLED":
                final_result = self._result("INCONCLUSIVE", "Order 2 ground truth was not CANCELLED after legitimate cancellation.", error="Cancellation ground truth mismatch.")
                return final_result

            # -------------------------------------------------------------
            # Step 8: Attempt Invalid Transition 3: Repeated Cancellation on Terminal State (CANCELLED -> CANCELLED)
            # -------------------------------------------------------------
            cancel2_repeat_result = self.client.post(
                f"/orders/{order2_id}/cancel",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_repeated_cancellation",
                endpoint=cancel2_repeat_result.endpoint,
                request_method="POST",
                request_headers=headers,
                result=cancel2_repeat_result,
            )
            if cancel2_repeat_result.status_code == 0:
                final_result = self._result("ERROR", "Repeated cancellation request failed at transport layer.", error=cancel2_repeat_result.error)
                return final_result

            truth2_post_repeat_cancel = self._verify_order(selected_mode, order2_id)
            self._record(
                step="verify_order2_ground_truth_post_repeat_cancel",
                endpoint=truth2_post_repeat_cancel.endpoint,
                request_method="GET",
                result=truth2_post_repeat_cancel,
            )
            valid_truth2_rep, ord2_rep_dict = self._valid_order_truth(truth2_post_repeat_cancel, order2_id, expected_user_id=user_id)
            if not valid_truth2_rep or ord2_rep_dict is None:
                final_result = self._result("INCONCLUSIVE", "Order 2 ground truth invalid after repeated cancellation attempt.", error="Post-repeat-cancel verification failed.")
                return final_result

            # -------------------------------------------------------------
            # Step 9: Attempt Invalid Transition 4: Illegal Resurrection of Cancelled Order (CANCELLED -> CONFIRMED)
            # -------------------------------------------------------------
            confirm2_resurrect_result = self.client.post(
                f"/orders/{order2_id}/confirm",
                mode=selected_mode,
                headers=headers,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_cancelled_order_confirmation",
                endpoint=confirm2_resurrect_result.endpoint,
                request_method="POST",
                request_headers=headers,
                result=confirm2_resurrect_result,
            )
            if confirm2_resurrect_result.status_code == 0:
                final_result = self._result("ERROR", "Resurrection confirmation request failed at transport layer.", error=confirm2_resurrect_result.error)
                return final_result

            truth2_post_resurrect = self._verify_order(selected_mode, order2_id)
            self._record(
                step="verify_order2_ground_truth_post_resurrect",
                endpoint=truth2_post_resurrect.endpoint,
                request_method="GET",
                result=truth2_post_resurrect,
            )
            valid_truth2_res, ord2_res_dict = self._valid_order_truth(truth2_post_resurrect, order2_id, expected_user_id=user_id)
            if not valid_truth2_res or ord2_res_dict is None:
                final_result = self._result("INCONCLUSIVE", "Order 2 ground truth invalid after resurrection attempt.", error="Post-resurrect verification failed.")
                return final_result

            # -------------------------------------------------------------
            # Step 10: Mode-Specific Evaluation and Synthesis
            # -------------------------------------------------------------
            if selected_mode == "vulnerable":
                # Check for vulnerable state machine bypasses
                unpaid_confirm_bypassed = (
                    confirm1_result.status_code == 200
                    and ord1_post_dict.get("status") == "CONFIRMED"
                )
                repeat_confirm_bypassed = (
                    confirm1_repeat_result.status_code == 200
                )
                repeat_cancel_bypassed = (
                    cancel2_repeat_result.status_code == 200
                )
                resurrect_bypassed = (
                    confirm2_resurrect_result.status_code == 200
                    and ord2_res_dict.get("status") == "CONFIRMED"
                )

                if unpaid_confirm_bypassed and repeat_confirm_bypassed and repeat_cancel_bypassed and resurrect_bypassed:
                    final_result = self._result(
                        "FAIL",
                        "Vulnerable mode permitted multiple invalid workflow transitions: unpaid confirmation, "
                        "repeated confirmation on terminal state, repeated cancellation on terminal state, and "
                        "resurrection of a cancelled order; admin ground truth confirms illegal state mutations.",
                    )
                elif unpaid_confirm_bypassed or resurrect_bypassed:
                    final_result = self._result(
                        "FAIL",
                        "Vulnerable mode permitted illegal order state machine transitions; "
                        "admin ground truth confirms unvalidated state transitions occurred.",
                    )
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        "Vulnerable mode did not exhibit the expected state machine bypasses.",
                        error="Expected invalid transitions were not accepted.",
                    )

            elif selected_mode == "secure":
                # Check secure enforcement of state machine invariants
                unpaid_confirm_rejected = (
                    self._expected_confirm_rejection(confirm1_result, "PENDING_PAYMENT")
                    and ord1_post_dict.get("status") == "PENDING_PAYMENT"
                )
                repeat_confirm_rejected = (
                    self._expected_confirm_rejection(confirm1_repeat_result, "PENDING_PAYMENT")
                )
                repeat_cancel_rejected = (
                    self._expected_cancel_rejection(cancel2_repeat_result, "CANCELLED")
                    and ord2_rep_dict.get("status") == "CANCELLED"
                )
                resurrect_rejected = (
                    self._expected_confirm_rejection(confirm2_resurrect_result, "CANCELLED")
                    and ord2_res_dict.get("status") == "CANCELLED"
                )

                if (
                    unpaid_confirm_rejected
                    and repeat_confirm_rejected
                    and repeat_cancel_rejected
                    and resurrect_rejected
                ):
                    final_result = self._result(
                        "PASS",
                        "Secure mode strictly enforced finite state machine invariants: unpaid confirmation was "
                        "rejected (HTTP 400), terminal states (CANCELLED) resisted mutation and repeated operations, "
                        "resurrection of cancelled orders was blocked, and legitimate transitions completed successfully.",
                    )
                elif (
                    confirm1_result.status_code == 200
                    or confirm2_resurrect_result.status_code == 200
                    or ord1_post_dict.get("status") == "CONFIRMED"
                    or ord2_res_dict.get("status") == "CONFIRMED"
                ):
                    final_result = self._result(
                        "FAIL",
                        "Secure mode permitted an illegal workflow transition; state machine was bypassed.",
                    )
                else:
                    final_result = self._result(
                        "ERROR",
                        "Secure mode returned unexpected responses during invalid transition attempts; "
                        "expected HTTP 400 finite state machine rejections were not observed.",
                        error="Unexpected transition response status or message.",
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

            # Cleanup residual cart if not checked out
            if cart_mutated and not (checkout1_completed and checkout2_completed) and session is not None and registered_user is not None:
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
