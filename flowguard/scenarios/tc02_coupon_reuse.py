"""TC-02: detect reuse of globally single-use coupons across multiple users."""

from __future__ import annotations

import uuid
from typing import Any

from ..auth import AuthSession, SyntheticUserManager
from ..client import FlowGuardClient
from ..config import ALLOWED_TARGET_MODES
from ..schemas import ApiResult, ScenarioResult
from .base import ScenarioBase, _TimedAuthClient


class TC02CouponReuseScenario(ScenarioBase):
    """Attempt globally single-use coupon reuse across multiple synthetic users.

    ShopZone exposes no coupon deletion or reset API through normal user routes.
    Synthetic users and completed orders therefore remain in the lab database;
    this scenario never resets it.
    Cleanup logs out and attempts to clear only the synthetic users' residual carts.
    Repeated runs on the same coupon can leave it exhausted unless re-seeded.
    """

    scenario_id = "TC-02"
    scenario_name = "Global Single-Use Coupon Reuse"
    expected_behavior = (
        "A globally single-use coupon must only be redeemed once across all users; "
        "vulnerable mode permits multiple users to redeem the coupon, "
        "while secure mode rejects subsequent redemptions."
    )

    def __init__(
        self,
        client: FlowGuardClient | None = None,
        *,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(client, timeout=timeout)

    def _verify_coupon(self, mode: str, code: str) -> ApiResult:
        headers = {"X-Admin-Key": self.client.config.admin_key} if self.client.config.admin_key else {}
        return self.client.get(
            f"/api/admin/verify/coupon/{mode}/{code}",
            headers=headers,
            timeout=self.timeout,
        )

    def _provision_coupon(
        self, mode: str, code: str, discount_pct: int = 20, max_uses: int = 1
    ) -> ApiResult:
        headers = {"X-Admin-Key": self.client.config.admin_key} if self.client.config.admin_key else {}
        return self.client.post(
            f"/api/admin/coupon/{mode}",
            headers=headers,
            json={"code": code, "discount_pct": discount_pct, "max_uses": max_uses},
            timeout=self.timeout,
        )

    @staticmethod
    def _valid_coupon_truth(
        result: ApiResult, expected_code: str
    ) -> tuple[bool, dict[str, Any] | None, list[dict[str, Any]] | None]:
        if result.status_code != 200 or not isinstance(result.payload, dict):
            return False, None, None
        if result.payload.get("found") is not True:
            return False, None, None

        coupon = result.payload.get("coupon")
        if not isinstance(coupon, dict):
            return False, None, None
        if coupon.get("code") != expected_code.upper():
            return False, None, None

        max_uses = coupon.get("max_uses")
        if not isinstance(max_uses, int) or isinstance(max_uses, bool):
            return False, None, None

        redemptions = result.payload.get("redemptions")
        if not isinstance(redemptions, list):
            return False, None, None

        redemption_count = result.payload.get("redemption_count")
        if (
            not isinstance(redemption_count, int)
            or isinstance(redemption_count, bool)
            or redemption_count != len(redemptions)
        ):
            return False, None, None

        for r in redemptions:
            if not isinstance(r, dict):
                return False, None, None
            uid = r.get("user_id")
            if not isinstance(uid, int) or isinstance(uid, bool):
                return False, None, None

        return True, coupon, redemptions

    @staticmethod
    def _expected_secure_rejection(result: ApiResult) -> bool:
        if result.status_code != 409 or not isinstance(result.payload, dict):
            return False
        if result.payload.get("error") != "Conflict":
            return False
        msg = str(result.payload.get("message", "")).lower()
        return "already been redeemed" in msg or "no longer available" in msg or "maximum usage limit" in msg

    def run(self, mode: str, coupon_code: str = "CYBERSEC20") -> ScenarioResult:
        self._begin()
        selected_mode = str(mode).lower()
        if selected_mode not in ALLOWED_TARGET_MODES:
            return self._result("ERROR", "Invalid ShopZone mode.", error="mode must be vulnerable or secure.")

        if not isinstance(coupon_code, str) or not coupon_code.strip():
            return self._result("ERROR", "Invalid coupon code.", error="coupon_code must be a non-empty string.")
        normalized_code = coupon_code.strip().upper()

        if not self.client.config.admin_key:
            return self._result(
                "INCONCLUSIVE",
                "Admin verification is not configured; no scenario requests were made.",
                error="ADMIN_KEY is required for independent ground-truth verification.",
            )

        # Baseline inspection: Verify coupon existence and initial state via ground truth
        initial_truth = self._verify_coupon(selected_mode, normalized_code)
        self._record(
            step="verify_initial_coupon_state",
            endpoint=initial_truth.endpoint,
            request_method="GET",
            result=initial_truth,
        )
        if initial_truth.status_code in (401, 403):
            return self._result(
                "INCONCLUSIVE",
                "Admin verification rejected credentials; cannot inspect ground truth.",
                error="ADMIN_KEY was invalid or rejected by admin endpoint.",
            )
        if initial_truth.status_code == 404:
            return self._result(
                "INCONCLUSIVE",
                f"Coupon '{normalized_code}' does not exist in {selected_mode} database.",
                error="Target coupon not found.",
            )

        valid_init, initial_coupon, initial_redemptions = self._valid_coupon_truth(initial_truth, normalized_code)
        if not valid_init or initial_coupon is None or initial_redemptions is None:
            return self._result(
                "INCONCLUSIVE",
                "Admin verification returned invalid initial coupon state.",
                error="Initial ground-truth verification was malformed.",
            )

        if initial_coupon.get("max_uses") != 1:
            return self._result(
                "INCONCLUSIVE",
                f"Coupon '{normalized_code}' has max_uses={initial_coupon.get('max_uses')}; TC-02 requires max_uses=1.",
                error="Target coupon is not configured as globally single-use.",
            )

        if len(initial_redemptions) > 0 or initial_coupon.get("times_used") != 0 or not initial_coupon.get("is_active"):
            return self._result(
                "INCONCLUSIVE",
                f"Coupon '{normalized_code}' is already exhausted, inactive, or previously redeemed.",
                error="Target coupon must be unused prior to scenario execution.",
            )

        manager = SyntheticUserManager(
            client=_TimedAuthClient(self.client, self.timeout),
            mode=selected_mode,
        )

        registered_user_a = None
        session_a: AuthSession | None = None
        user_a_cart_mutated = False
        user_a_checkout_completed = False

        registered_user_b = None
        session_b: AuthSession | None = None
        user_b_cart_mutated = False
        user_b_checkout_completed = False

        final_result: ScenarioResult | None = None
        cleanup_evidence_start = 0

        try:
            # -------------------------------------------------------------
            # User A: Register, Login, Cart, Apply Coupon, Checkout
            # -------------------------------------------------------------
            username_a = manager.generate_username("tc02_a")
            email_a = manager.generate_email(username_a)
            password_a = manager.generate_password()

            registered_user_a = manager.register_user(
                username_a,
                email_a,
                password_a,
                mode=selected_mode,
            )
            if registered_user_a is None:
                final_result = self._result("ERROR", "Registration failed for user A.", error="HTTP registration failed.")
                return final_result

            user_a_id = registered_user_a.user_id
            if not isinstance(user_a_id, int) or isinstance(user_a_id, bool):
                final_result = self._result("ERROR", "Registered user A has malformed identity.", error="user_id must be integer.")
                return final_result

            session_a = manager.login_user(registered_user_a, mode=selected_mode)
            if not session_a.authenticated:
                final_result = self._result("ERROR", "Authentication failed for user A.", error=session_a.session_metadata.get("error"))
                return final_result

            headers_a = manager.get_auth_headers(registered_user_a.username, mode=selected_mode)

            # Retrieve product catalog
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

            # Add product to User A's cart
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
            user_a_cart_mutated = True

            # Apply coupon for User A
            apply_a_result = self.client.post(
                "/coupons/apply",
                mode=selected_mode,
                headers=headers_a,
                json={"code": normalized_code},
                timeout=self.timeout,
            )
            self._record(
                step="apply_coupon_user_a",
                endpoint=apply_a_result.endpoint,
                request_method="POST",
                request_payload={"code": normalized_code},
                request_headers=headers_a,
                result=apply_a_result,
            )
            if not (200 <= apply_a_result.status_code < 300):
                final_result = self._result("ERROR", "Initial coupon application failed for user A.", error="Coupon apply endpoint failed.")
                return final_result

            # User A completes checkout
            checkout_a_payload = {
                "idempotency_key": f"tc02-a-{uuid.uuid4().hex}",
                "coupon_code": normalized_code,
            }
            checkout_a_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers_a,
                json=checkout_a_payload,
                timeout=self.timeout,
            )
            self._record(
                step="checkout_user_a",
                endpoint=checkout_a_result.endpoint,
                request_method="POST",
                request_payload=checkout_a_payload,
                request_headers=headers_a,
                result=checkout_a_result,
            )
            checkout_a_body = checkout_a_result.payload
            order_a = checkout_a_body.get("order") if isinstance(checkout_a_body, dict) else None
            candidate_a_id = order_a.get("id") if isinstance(order_a, dict) else None
            order_a_user_id = order_a.get("user_id") if isinstance(order_a, dict) else None
            if (
                not (200 <= checkout_a_result.status_code < 300)
                or not isinstance(order_a, dict)
                or not isinstance(candidate_a_id, int)
                or isinstance(candidate_a_id, bool)
                or not isinstance(order_a_user_id, int)
                or isinstance(order_a_user_id, bool)
                or order_a_user_id != user_a_id
                or order_a.get("status") != "PENDING_PAYMENT"
            ):
                final_result = self._result("ERROR", "Initial checkout with coupon failed for user A.", error="Checkout did not return a valid order.")
                return final_result

            user_a_checkout_completed = True

            # -------------------------------------------------------------
            # User B: Register, Login, Cart, Attempt Checkout With Same Coupon
            # -------------------------------------------------------------
            username_b = manager.generate_username("tc02_b")
            email_b = manager.generate_email(username_b)
            password_b = manager.generate_password()

            registered_user_b = manager.register_user(
                username_b,
                email_b,
                password_b,
                mode=selected_mode,
            )
            if registered_user_b is None:
                final_result = self._result("ERROR", "Registration failed for user B.", error="HTTP registration failed for user B.")
                return final_result

            user_b_id = registered_user_b.user_id
            if not isinstance(user_b_id, int) or isinstance(user_b_id, bool) or user_b_id == user_a_id:
                final_result = self._result("ERROR", "Registered user B has malformed identity.", error="user_id must be distinct integer.")
                return final_result

            session_b = manager.login_user(registered_user_b, mode=selected_mode)
            if not session_b.authenticated:
                final_result = self._result("ERROR", "Authentication failed for user B.", error=session_b.session_metadata.get("error"))
                return final_result

            headers_b = manager.get_auth_headers(registered_user_b.username, mode=selected_mode)

            # Add product to User B's cart
            cart_b_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers_b,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="add_product_to_cart_user_b",
                endpoint=cart_b_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers_b,
                result=cart_b_result,
            )
            cart_b_payload = cart_b_result.payload
            cart_b_item = cart_b_payload.get("cart_item") if isinstance(cart_b_payload, dict) else None
            if not (200 <= cart_b_result.status_code < 300) or not isinstance(cart_b_item, dict):
                final_result = self._result("ERROR", "Cart creation failed for user B.", error="A validated cart item was not returned.")
                return final_result
            user_b_cart_mutated = True

            # User B attempts to checkout with the SAME coupon
            checkout_b_payload = {
                "idempotency_key": f"tc02-b-{uuid.uuid4().hex}",
                "coupon_code": normalized_code,
            }
            checkout_b_result = self.client.post(
                "/orders/checkout",
                mode=selected_mode,
                headers=headers_b,
                json=checkout_b_payload,
                timeout=self.timeout,
            )
            self._record(
                step="attempt_coupon_reuse_user_b",
                endpoint=checkout_b_result.endpoint,
                request_method="POST",
                request_payload=checkout_b_payload,
                request_headers=headers_b,
                result=checkout_b_result,
                observed_state={"http_status": checkout_b_result.status_code},
            )

            if 200 <= checkout_b_result.status_code < 300:
                order_b = checkout_b_result.payload.get("order") if isinstance(checkout_b_result.payload, dict) else None
                cand_b_id = order_b.get("id") if isinstance(order_b, dict) else None
                order_b_user_id = order_b.get("user_id") if isinstance(order_b, dict) else None
                if (
                    isinstance(order_b, dict)
                    and isinstance(cand_b_id, int)
                    and not isinstance(cand_b_id, bool)
                    and order_b_user_id == user_b_id
                ):
                    user_b_checkout_completed = True

            # -------------------------------------------------------------
            # Ground-Truth Verification
            # -------------------------------------------------------------
            final_truth = self._verify_coupon(selected_mode, normalized_code)
            self._record(
                step="verify_final_coupon_state",
                endpoint=final_truth.endpoint,
                request_method="GET",
                result=final_truth,
            )

            valid_final, final_coupon, final_redemptions = self._valid_coupon_truth(final_truth, normalized_code)
            if not valid_final or final_coupon is None or final_redemptions is None:
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Admin verification did not provide complete coupon ground-truth evidence.",
                    error="Final ground-truth verification was missing or malformed.",
                )
                return final_result

            redeemed_user_ids = [
                r.get("user_id")
                for r in final_redemptions
                if isinstance(r.get("user_id"), int) and not isinstance(r.get("user_id"), bool)
            ]

            if user_a_id not in redeemed_user_ids:
                final_result = self._result(
                    "INCONCLUSIVE",
                    "Admin verification does not show initial redemption by user A.",
                    error="User A redemption not reflected in ground truth.",
                )
                return final_result

            user_b_redeemed = user_b_id in redeemed_user_ids
            total_redemptions = len(final_redemptions)

            # -------------------------------------------------------------
            # Classification
            # -------------------------------------------------------------
            if selected_mode == "vulnerable":
                if checkout_b_result.ok and user_b_redeemed and total_redemptions >= 2:
                    final_result = self._result(
                        "FAIL",
                        "Admin verification confirms a globally single-use coupon was redeemed by multiple users.",
                    )
                elif not checkout_b_result.ok and not user_b_redeemed:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        "Vulnerable mode did not permit coupon reuse; expected bypass was not observed.",
                    )
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        "Contradictory evidence between checkout response and admin ground truth in vulnerable mode.",
                        error=f"HTTP ok={checkout_b_result.ok}, user_b_redeemed={user_b_redeemed}, count={total_redemptions}.",
                    )
            elif selected_mode == "secure":
                if self._expected_secure_rejection(checkout_b_result) and not user_b_redeemed and total_redemptions == 1:
                    final_result = self._result(
                        "PASS",
                        "Admin verification confirms only the first user redeemed the globally single-use coupon; subsequent redemption was rejected.",
                    )
                elif checkout_b_result.ok or user_b_redeemed or total_redemptions > 1:
                    final_result = self._result(
                        "FAIL",
                        "Secure mode permitted multiple redemptions of a globally single-use coupon.",
                    )
                else:
                    final_result = self._result(
                        "ERROR",
                        f"Secure coupon reuse returned unexpected HTTP {checkout_b_result.status_code}; expected business rejection was not observed.",
                        error="Unexpected second checkout response; not classified as a security PASS.",
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

            # Cleanup User A's uncompleted cart
            if user_a_cart_mutated and not user_a_checkout_completed and session_a is not None and registered_user_a is not None:
                try:
                    res_headers_a = manager.get_auth_headers(registered_user_a.username, mode=selected_mode)
                    if res_headers_a:
                        clear_a = self.client.delete("/cart", mode=selected_mode, headers=res_headers_a, timeout=self.timeout)
                        self._record(
                            step="cleanup_residual_cart_user_a",
                            endpoint=clear_a.endpoint,
                            request_method="DELETE",
                            request_headers=res_headers_a,
                            result=clear_a,
                        )
                except Exception:
                    self._record(
                        step="cleanup_cart_error_user_a",
                        endpoint=f"/{selected_mode}/api/cart",
                        request_method="DELETE",
                        error="Residual cart cleanup failed for user A.",
                    )

            # Logout User A
            if session_a is not None and session_a.authenticated and registered_user_a is not None:
                try:
                    logout_headers_a = dict(session_a.authentication_headers)
                    logout_a = manager.logout_user(registered_user_a, mode=selected_mode)
                    self._record(
                        step="logout_synthetic_user_a",
                        endpoint=logout_a.endpoint,
                        request_method="POST",
                        request_headers=logout_headers_a,
                        result=logout_a,
                    )
                except Exception:
                    self._record(
                        step="logout_synthetic_user_a_error",
                        endpoint=f"/{selected_mode}/api/auth/logout",
                        request_method="POST",
                        error="Synthetic user A logout failed.",
                    )

            # Cleanup User B's uncompleted cart
            if user_b_cart_mutated and not user_b_checkout_completed and session_b is not None and registered_user_b is not None:
                try:
                    res_headers_b = manager.get_auth_headers(registered_user_b.username, mode=selected_mode)
                    if res_headers_b:
                        clear_b = self.client.delete("/cart", mode=selected_mode, headers=res_headers_b, timeout=self.timeout)
                        self._record(
                            step="cleanup_residual_cart_user_b",
                            endpoint=clear_b.endpoint,
                            request_method="DELETE",
                            request_headers=res_headers_b,
                            result=clear_b,
                        )
                except Exception:
                    self._record(
                        step="cleanup_cart_error_user_b",
                        endpoint=f"/{selected_mode}/api/cart",
                        request_method="DELETE",
                        error="Residual cart cleanup failed for user B.",
                    )

            # Logout User B
            if session_b is not None and session_b.authenticated and registered_user_b is not None:
                try:
                    logout_headers_b = dict(session_b.authentication_headers)
                    logout_b = manager.logout_user(registered_user_b, mode=selected_mode)
                    self._record(
                        step="logout_synthetic_user_b",
                        endpoint=logout_b.endpoint,
                        request_method="POST",
                        request_headers=logout_headers_b,
                        result=logout_b,
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
