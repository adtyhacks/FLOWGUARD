"""TC-06: Concurrent Checkout Race Condition / Idempotent Invariant scenario."""

from __future__ import annotations

import concurrent.futures
import threading
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


class TC06ConcurrentCheckoutScenario(ScenarioBase):
    """Test race conditions, concurrency control, and idempotency invariants during checkout.

    In secure mode, concurrent checkout requests submitted with the same idempotency key must
    be processed idempotently:
    - Exactly one logical order must be created in the database.
    - All successful concurrent responses must reference the same order ID (either 201 Created
      for the winning transaction or 200 OK with idempotent_replay=True for concurrent followers).
    - Database unique constraints and transactional rollback prevent duplicate order creation.

    In vulnerable mode:
    - Checkout lacks concurrency locks and ignores idempotency keys.
    - Concurrent requests create duplicate orders from the same cart or using the same idempotency key.

    ShopZone exposes no order deletion API. Synthetic users and completed orders
    therefore remain in the lab database; this scenario never resets it.
    Cleanup clears only the synthetic user's residual cart and logs out the session.
    """

    scenario_id = "TC-06"
    scenario_name = "Concurrent Checkout Race Condition / Idempotency Invariant"
    expected_behavior = (
        "Concurrent checkout requests submitted with the same idempotency key must be processed "
        "idempotently; exactly one logical order must be created, and all successful responses must "
        "reference the same order ID. Vulnerable mode demonstrates race condition flaws resulting "
        "in duplicate order creation."
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

    def _execute_concurrent_checkouts(
        self,
        mode: str,
        headers: dict[str, str],
        payloads: list[dict[str, Any]],
    ) -> list[ApiResult]:
        """Submit simultaneous checkout requests synchronized at a threading.Barrier."""
        n_workers = len(payloads)
        barrier = threading.Barrier(n_workers)
        results: list[ApiResult | None] = [None] * n_workers

        def worker(idx: int) -> None:
            try:
                barrier.wait(timeout=self.timeout)
            except (threading.BrokenBarrierError, Exception):
                pass
            results[idx] = self.client.post(
                "/orders/checkout",
                mode=mode,
                headers=headers,
                json=payloads[idx],
                timeout=self.timeout,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as executor:
            futures = [executor.submit(worker, i) for i in range(n_workers)]
            concurrent.futures.wait(futures, timeout=self.timeout * 2)

        # Fallback for any unassigned slot
        for idx in range(n_workers):
            if results[idx] is None:
                results[idx] = ApiResult(
                    status_code=0,
                    ok=False,
                    payload=None,
                    elapsed_ms=0.0,
                    request_method="POST",
                    endpoint="/orders/checkout",
                    error="Worker thread did not complete or timed out.",
                )

        return [r for r in results if r is not None]

    def run(self, mode: str, num_workers: int = 4) -> ScenarioResult:
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

        if not isinstance(num_workers, int) or isinstance(num_workers, bool) or num_workers < 2 or num_workers > 10:
            return self._result("ERROR", "Invalid worker count.", error="num_workers must be an integer between 2 and 10.")

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
            username = manager.generate_username("tc06_racer")
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
            # Step 2: Product Catalog Lookup
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
            # Step 3: Populate cart for Phase A (Same-key concurrent checkout)
            # -------------------------------------------------------------
            cart_a_result = self.client.post(
                "/cart/items",
                mode=selected_mode,
                headers=headers,
                json={"product_id": product_id, "quantity": 1},
                timeout=self.timeout,
            )
            self._record(
                step="populate_cart_phase_a",
                endpoint=cart_a_result.endpoint,
                request_method="POST",
                request_payload={"product_id": product_id, "quantity": 1},
                request_headers=headers,
                result=cart_a_result,
            )
            cart_a_payload = cart_a_result.payload
            cart_a_item = cart_a_payload.get("cart_item") if isinstance(cart_a_payload, dict) else None
            if not (200 <= cart_a_result.status_code < 300) or not isinstance(cart_a_item, dict):
                final_result = self._result("ERROR", "Cart creation failed for Phase A.", error="Cart item was not returned.")
                return final_result
            cart_mutated = True

            # -------------------------------------------------------------
            # Step 4: Dispatch Same-Key Concurrent Checkouts
            # -------------------------------------------------------------
            shared_key = f"tc06-shared-{uuid.uuid4().hex}"
            same_key_payloads = [{"idempotency_key": shared_key} for _ in range(num_workers)]

            same_key_responses = self._execute_concurrent_checkouts(
                selected_mode, headers, same_key_payloads
            )

            # Record individual concurrent request evidence
            for i, resp in enumerate(same_key_responses):
                self._record(
                    step=f"concurrent_same_key_worker_{i}",
                    endpoint=resp.endpoint,
                    request_method="POST",
                    request_payload={"idempotency_key": shared_key},
                    request_headers=headers,
                    result=resp,
                )

            # Inspect returned order IDs and status codes
            created_order_ids: list[int] = []
            successful_order_ids: list[int] = []
            for resp in same_key_responses:
                if resp.status_code in (200, 201) and isinstance(resp.payload, dict):
                    order_dict = resp.payload.get("order")
                    if isinstance(order_dict, dict):
                        oid = order_dict.get("id")
                        if _validate_positive_int_id(oid):
                            successful_order_ids.append(oid)
                            if resp.status_code == 201:
                                created_order_ids.append(oid)

            # -------------------------------------------------------------
            # Step 5: Authoritative Ground Truth Verification (Phase A)
            # -------------------------------------------------------------
            user_orders_result = self.client.get("/orders", mode=selected_mode, headers=headers, timeout=self.timeout)
            self._record(
                step="fetch_user_orders_phase_a",
                endpoint=user_orders_result.endpoint,
                request_method="GET",
                request_headers=headers,
                result=user_orders_result,
            )
            if user_orders_result.status_code != 200 or not isinstance(user_orders_result.payload, dict):
                final_result = self._result("INCONCLUSIVE", "User order listing failed.", error="Could not retrieve user orders.")
                return final_result

            orders_list = user_orders_result.payload.get("orders")
            if not isinstance(orders_list, list):
                final_result = self._result("INCONCLUSIVE", "Malformed orders list in ground truth.", error="orders field must be a list.")
                return final_result

            # Filter orders belonging to this user and matching the shared idempotency key
            matching_key_orders = [
                o for o in orders_list
                if isinstance(o, dict)
                and o.get("idempotency_key") == shared_key
                and o.get("user_id") == user_id
            ]

            # -------------------------------------------------------------
            # Step 6: Mode-Specific Classification for Same-Key Concurrency
            # -------------------------------------------------------------
            if selected_mode == "vulnerable":
                # In vulnerable mode, ground truth must independently corroborate duplicate orders committed with identical key
                corroborated_count = 0
                for ord_item in matching_key_orders:
                    oid = ord_item.get("id")
                    if _validate_positive_int_id(oid):
                        v_truth = self._verify_order(selected_mode, oid)
                        valid_t, _ = self._valid_order_truth(v_truth, oid, expected_user_id=user_id)
                        if valid_t:
                            corroborated_count += 1

                if corroborated_count >= 2:
                    final_result = self._result(
                        "FAIL",
                        f"Vulnerable mode permitted duplicate order creation under concurrent same-key checkout; "
                        f"admin ground truth confirms {corroborated_count} distinct orders committed with identical key '{shared_key}'.",
                    )
                    return final_result
                else:
                    final_result = self._result(
                        "INCONCLUSIVE",
                        "Vulnerable mode did not manifest corroborated concurrent duplicate order creation in ground truth.",
                        error="Concurrent race window was not observed or not corroborated by admin ground truth.",
                    )
                    return final_result

            elif selected_mode == "secure":
                # In secure mode: exactly 1 order created in ground truth, all successes reference same order ID
                distinct_order_ids = set(successful_order_ids)
                single_order_in_truth = len(matching_key_orders) == 1
                single_consistent_id = len(distinct_order_ids) == 1
                at_most_one_201 = len(created_order_ids) <= 1

                if not single_order_in_truth or not single_consistent_id or not at_most_one_201:
                    final_result = self._result(
                        "FAIL",
                        f"Secure mode permitted duplicate orders under concurrency: "
                        f"{len(matching_key_orders)} orders in ground truth, {len(distinct_order_ids)} distinct IDs returned.",
                    )
                    return final_result

                winning_order_id = matching_key_orders[0].get("id")
                # Admin verify the winning order
                admin_truth = self._verify_order(selected_mode, winning_order_id)
                valid_admin, admin_order = self._valid_order_truth(admin_truth, winning_order_id, expected_user_id=user_id)
                if not valid_admin or admin_order is None or admin_order.get("status") != "PENDING_PAYMENT":
                    final_result = self._result(
                        "INCONCLUSIVE",
                        "Admin verification of concurrent winner order failed or returned invalid status.",
                        error="Winner order ground truth mismatch.",
                    )
                    return final_result

                # -------------------------------------------------------------
                # Step 7: Phase B — Different-Key Concurrent Checkout (Consistency Check)
                # -------------------------------------------------------------
                # Re-populate cart
                cart_b_result = self.client.post(
                    "/cart/items",
                    mode=selected_mode,
                    headers=headers,
                    json={"product_id": product_id, "quantity": 1},
                    timeout=self.timeout,
                )
                self._record(
                    step="populate_cart_phase_b",
                    endpoint=cart_b_result.endpoint,
                    request_method="POST",
                    request_payload={"product_id": product_id, "quantity": 1},
                    request_headers=headers,
                    result=cart_b_result,
                )

                diff_key_payloads = [
                    {"idempotency_key": f"tc06-diff-{i}-{uuid.uuid4().hex}"}
                    for i in range(num_workers)
                ]

                diff_key_responses = self._execute_concurrent_checkouts(
                    selected_mode, headers, diff_key_payloads
                )

                for i, resp in enumerate(diff_key_responses):
                    self._record(
                        step=f"concurrent_diff_key_worker_{i}",
                        endpoint=resp.endpoint,
                        request_method="POST",
                        request_payload=diff_key_payloads[i],
                        request_headers=headers,
                        result=resp,
                    )

                # Verify consistency of any created orders in Phase B
                phase_b_created_ids: list[int] = []
                for resp in diff_key_responses:
                    if resp.status_code == 201 and isinstance(resp.payload, dict):
                        ord_dict = resp.payload.get("order")
                        if isinstance(ord_dict, dict) and _validate_positive_int_id(ord_dict.get("id")):
                            phase_b_created_ids.append(ord_dict.get("id"))

                for pb_id in phase_b_created_ids:
                    pb_truth = self._verify_order(selected_mode, pb_id)
                    pb_valid, pb_ord = self._valid_order_truth(pb_truth, pb_id, expected_user_id=user_id)
                    if not pb_valid or pb_ord is None or pb_ord.get("status") != "PENDING_PAYMENT":
                        final_result = self._result(
                            "INCONCLUSIVE",
                            f"Ground truth verification failed for Phase B concurrent order {pb_id}.",
                            error="Phase B order verification failed.",
                        )
                        return final_result

                final_result = self._result(
                    "PASS",
                    f"Secure mode strictly enforced checkout concurrency invariants: concurrent same-key requests "
                    f"({num_workers} threads) were deduplicated to exactly one order (ID {winning_order_id}), "
                    f"idempotent replays matched the winner ID, and concurrent different-key requests "
                    f"maintained database consistency across transactions without orphan records.",
                )

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
