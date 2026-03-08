"""
Stripe billing endpoints.

POST /billing/checkout  — create a Stripe Checkout session (upgrade to Pro)
POST /billing/portal    — create a Stripe Billing Portal session (manage sub)
POST /billing/webhook   — handle Stripe webhook events (signature-verified)

Webhook events handled:
  checkout.session.completed          → activate Pro plan
  customer.subscription.updated       → sync plan/status changes (renewals, past_due)
  customer.subscription.deleted       → downgrade to Free

Setup:
  1. In Stripe dashboard, create a Product "Pro" with a $19/mo recurring price.
  2. Copy the price ID (price_...) → STRIPE_PRO_PRICE_ID in .env
  3. Add a webhook endpoint in Stripe → https://api.misconfig.dev/billing/webhook
     Events: checkout.session.completed, customer.subscription.updated,
             customer.subscription.deleted
  4. Copy the webhook signing secret (whsec_...) → STRIPE_WEBHOOK_SECRET in .env
"""
from __future__ import annotations

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..deps import get_db
from ..models import User
from ..routers.auth import get_current_user

router = APIRouter()


def _stripe() -> None:
    """Configure stripe API key; raise 503 if not set."""
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing is not configured")
    stripe.api_key = settings.STRIPE_SECRET_KEY


# ── POST /billing/checkout ────────────────────────────────────────────────────

@router.post("/checkout")
def create_checkout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Create a Stripe Checkout session for upgrading to Pro.
    Returns {checkout_url: str} — the frontend should redirect to this URL.
    """
    _stripe()

    if not settings.STRIPE_PRO_PRICE_ID:
        raise HTTPException(status_code=503, detail="Pro plan not configured")

    if current_user.plan == "pro" and current_user.plan_status == "active":
        raise HTTPException(status_code=400, detail="Already on an active Pro plan")

    # Create a Stripe Customer if this user doesn't have one yet
    if not current_user.stripe_customer_id:
        customer = stripe.Customer.create(
            email=current_user.github_email or "",
            name=current_user.github_login,
            metadata={
                "user_id": str(current_user.id),
                "github_login": current_user.github_login,
            },
        )
        current_user.stripe_customer_id = customer.id
        db.commit()

    session = stripe.checkout.Session.create(
        customer=current_user.stripe_customer_id,
        line_items=[{"price": settings.STRIPE_PRO_PRICE_ID, "quantity": 1}],
        mode="subscription",
        success_url=f"{settings.FRONTEND_URL}/account/?upgrade=success",
        cancel_url=f"{settings.FRONTEND_URL}/pricing/",
        allow_promotion_codes=True,
        billing_address_collection="auto",
    )

    return {"checkout_url": session.url}


# ── POST /billing/portal ──────────────────────────────────────────────────────

@router.post("/portal")
def create_portal(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Create a Stripe Billing Portal session so the user can manage their
    subscription, update payment method, or cancel.
    Returns {portal_url: str}.
    """
    _stripe()

    if not current_user.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No billing account found — upgrade to Pro first",
        )

    session = stripe.billing_portal.Session.create(
        customer=current_user.stripe_customer_id,
        return_url=f"{settings.FRONTEND_URL}/account/",
    )

    return {"portal_url": session.url}


# ── POST /billing/webhook ─────────────────────────────────────────────────────

@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(None, alias="stripe-signature"),
    db: Session = Depends(get_db),
) -> dict:
    """
    Stripe sends signed events here. We verify the signature before acting.
    This endpoint must NOT be rate-limited (Stripe retries on failure).
    """
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured")

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data = event["data"]["object"]

    # ── checkout.session.completed → activate Pro ─────────────────────────────
    if event_type == "checkout.session.completed":
        customer_id = data.get("customer")
        subscription_id = data.get("subscription")

        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.plan = "pro"
            user.plan_status = "active"
            if subscription_id:
                user.stripe_subscription_id = subscription_id
            db.commit()

    # ── customer.subscription.updated → sync status ───────────────────────────
    elif event_type == "customer.subscription.updated":
        customer_id = data.get("customer")
        status = data.get("status", "")  # "active" | "past_due" | "canceled" | ...

        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.plan_status = status
            user.plan = "pro" if status in ("active", "trialing") else "free"
            db.commit()

    # ── customer.subscription.deleted → downgrade ─────────────────────────────
    elif event_type == "customer.subscription.deleted":
        customer_id = data.get("customer")

        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        if user:
            user.plan = "free"
            user.plan_status = "canceled"
            user.stripe_subscription_id = None
            db.commit()

    return {"received": True}
