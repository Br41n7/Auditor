"""Read-only payment integration checks for authorized applications."""
import re
from ..core.models import Finding
from ..recon.discovery import candidate_paths

# Used only if the crawl found nothing payment-shaped -- e.g. payment
# routes live behind a login wall the crawler never authenticated into.
_FALLBACK_PAYMENT_PATHS = (
    "/api/paystack/verify", "/api/payment/verify", "/api/payments/verify",
    "/api/webhooks/paystack", "/api/paystack/webhook", "/api/payments",
    "/api/checkout", "/api/orders", "/api/refunds", "/api/withdrawals",
)
_PAYMENT_KEYWORDS = ("pay", "paystack", "checkout", "refund", "withdraw", "wallet", "transaction", "billing", "order")
REFERENCE_RE = re.compile(r"(?:reference|transaction|trx|payment)[_-]?(?:id|ref|reference)?", re.I)


def scan(client, reporter):
    for path in candidate_paths(client, _PAYMENT_KEYWORDS, _FALLBACK_PAYMENT_PATHS):
        try:
            r = client.request("GET", path, allow_redirects=False)
        except Exception:
            continue
        if r.status_code in {404, 405}:
            continue
        reporter.info(f"Payment surface {path}: HTTP {r.status_code}")
        if path.endswith("verify") and r.status_code == 200:
            reporter.add(Finding(
                "MEDIUM", "payments", "Payment verification endpoint is publicly reachable",
                f"GET {path} returned HTTP 200 without an explicit authentication header.",
                "Require appropriate authorization and verify the transaction server-side. Bind fulfillment to the verified transaction reference, expected amount, currency and application order; make fulfillment idempotent.",
                r.url, confidence="medium", check_id="payments.verify-exposure"
            ))
        if "webhook" in path and r.status_code == 200:
            reporter.add(Finding(
                "LOW", "payments", "Webhook endpoint responds to unauthenticated GET",
                f"GET {path} returned HTTP 200. A GET response alone does not prove webhook forgery is possible.",
                "For Paystack webhooks, validate the x-paystack-signature HMAC (or use documented IP allowlisting) before processing events and keep processing idempotent.",
                r.url, confidence="low", check_id="payments.webhook-review"
            ))


def verify_paystack_transaction(client, reporter, secret_key, reference, expected_amount=None, expected_currency=None):
    """Verify one transaction using the caller's own Paystack integration key.

    This performs only Paystack's documented GET verification call; it does not
    initialize, charge, refund, transfer, or mutate a transaction.
    """
    if not secret_key:
        raise ValueError("Paystack verification requires --paystack-secret-key or AUDITOR_PAYSTACK_SECRET_KEY")
    if not reference:
        raise ValueError("A Paystack transaction reference is required")
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    try:
        r = client.session.get(url, headers={"Authorization": f"Bearer {secret_key}"}, timeout=client.timeout, verify=client.verify)
    except Exception as exc:
        reporter.error(f"Paystack verification failed: {exc}")
        return
    if r.status_code != 200:
        reporter.add(Finding("MEDIUM", "payments", "Paystack transaction verification failed", f"Paystack returned HTTP {r.status_code} for the supplied reference.", "Check the reference, environment and server-side Paystack configuration.", url, confidence="high", check_id="payments.paystack-verify"))
        return
    try:
        body = r.json()
        data = body.get("data") or {}
        status = data.get("status")
        amount = data.get("amount")
        currency = data.get("currency")
        reporter.info(f"Paystack transaction {reference}: status={status}, amount={amount}, currency={currency}")
        if expected_amount is not None and str(amount) != str(expected_amount):
            reporter.add(Finding("HIGH", "payments", "Verified payment amount differs from expected amount", f"Expected {expected_amount}, Paystack verified {amount}.", "Do not fulfill from client-supplied amounts. Compare the verified gateway amount with the server-side order total before fulfillment.", url, confidence="high", check_id="payments.amount-mismatch"))
        if expected_currency and str(currency).upper() != str(expected_currency).upper():
            reporter.add(Finding("HIGH", "payments", "Verified payment currency differs from expected currency", f"Expected {expected_currency}, Paystack verified {currency}.", "Bind fulfillment to the expected currency as well as the amount and transaction reference.", url, confidence="high", check_id="payments.currency-mismatch"))
        if status != "success":
            reporter.add(Finding("MEDIUM", "payments", "Transaction is not successful", f"Paystack returned transaction status {status!r}.", "Only fulfill paid value after the gateway reports success and your application confirms the transaction has not already been fulfilled.", url, confidence="high", check_id="payments.unsuccessful-transaction"))
    except Exception:
        reporter.add(Finding("MEDIUM", "payments", "Unexpected Paystack verification response", "The verification endpoint returned HTTP 200 but the JSON shape was not recognized.", "Review the Paystack response and ensure your integration handles gateway errors safely.", url, confidence="medium", check_id="payments.verify-response"))
