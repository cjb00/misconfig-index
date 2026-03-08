"""
GitHub OAuth 2.0 authentication.

Flow:
  1. Browser → GET /auth/github/login
             ← 302 redirect to github.com/login/oauth/authorize
  2. GitHub  → GET /auth/github/callback?code=xxx
             ← 302 redirect to FRONTEND_URL/dashboard/?token=<JWT>
  3. Frontend stores JWT in localStorage, sends as Authorization: Bearer <JWT>

Endpoints:
  GET /auth/github/login     — start OAuth flow
  GET /auth/github/callback  — handle GitHub redirect, issue JWT
  GET /auth/me               — return current user (requires JWT)
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..config import settings
from ..deps import get_db
from ..models import Organization, User, UserOrg
from ..ratelimit import limiter

router = APIRouter()

# ── JWT helpers ───────────────────────────────────────────────────────────────

def _make_jwt(user_id: int, github_login: str) -> str:
    payload = {
        "sub": str(user_id),
        "login": github_login,
        "exp": datetime.now(timezone.utc) + timedelta(days=settings.JWT_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency — validates Bearer JWT and returns the User."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    payload = decode_jwt(token)
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ── OAuth endpoints ───────────────────────────────────────────────────────────

@router.get("/github/login")
@limiter.limit("20/minute")
def github_login(request: Request):
    """Redirect browser to GitHub OAuth consent screen."""
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(status_code=503, detail="GitHub OAuth not configured")

    params = urlencode({
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": f"{settings.API_URL}/auth/github/callback",
        "scope": "read:user user:email",
        "state": secrets.token_hex(16),
    })
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{params}")


@router.get("/github/callback")
@limiter.limit("20/minute")
def github_callback(request: Request, code: str, db: Session = Depends(get_db)):
    """
    GitHub redirects here after the user grants permission.
    Exchanges the code for a GitHub access token, upserts the user,
    and redirects the browser to the frontend with a JWT.
    """
    if not settings.GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=503, detail="GitHub OAuth not configured")

    # 1. Exchange code for GitHub access token
    with httpx.Client(timeout=10) as client:
        token_res = client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{settings.API_URL}/auth/github/callback",
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_res.json()

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="GitHub OAuth failed — bad code")

    # 2. Fetch GitHub user profile
    with httpx.Client(timeout=10) as client:
        gh_headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        user_res = client.get("https://api.github.com/user", headers=gh_headers)
        gh_user = user_res.json()

        # Fetch verified email if not public
        email = gh_user.get("email")
        if not email:
            emails_res = client.get("https://api.github.com/user/emails", headers=gh_headers)
            for e in emails_res.json():
                if e.get("primary") and e.get("verified"):
                    email = e["email"]
                    break

    github_id = gh_user.get("id")
    if not github_id:
        raise HTTPException(status_code=400, detail="Could not retrieve GitHub user info")

    # 3. Upsert user in DB
    user = db.query(User).filter(User.github_id == github_id).first()
    if user:
        user.github_login = gh_user["login"]
        user.github_email = email
        user.avatar_url = gh_user.get("avatar_url")
        user.last_login_at = datetime.utcnow()
    else:
        user = User(
            github_id=github_id,
            github_login=gh_user["login"],
            github_email=email,
            avatar_url=gh_user.get("avatar_url"),
        )
        db.add(user)
    db.commit()
    db.refresh(user)

    # 4. Issue JWT and redirect to frontend (root page picks up token from URL)
    token = _make_jwt(user.id, user.github_login)
    redirect_url = f"{settings.FRONTEND_URL}/?token={token}"
    return RedirectResponse(redirect_url)


# ── /auth/me ─────────────────────────────────────────────────────────────────

@router.get("/me")
def me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return the currently authenticated user and their orgs."""
    orgs = [
        {
            "id": uo.org.id,
            "name": uo.org.name,
            "slug": uo.org.slug,
            "role": uo.role,
        }
        for uo in current_user.user_orgs
    ]
    return {
        "id": current_user.id,
        "github_login": current_user.github_login,
        "github_email": current_user.github_email,
        "avatar_url": current_user.avatar_url,
        "created_at": current_user.created_at,
        "plan": current_user.plan or "free",
        "plan_status": current_user.plan_status,
        "orgs": orgs,
    }


@router.get("/my-repos")
def my_repos(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return all repos tracked under any org the authenticated user belongs to."""
    from .. import crud

    result = []
    for uo in current_user.user_orgs:
        repos = crud.get_repos(db, uo.org)
        result.append({
            "org_id": uo.org.id,
            "org_name": uo.org.name,
            "org_slug": uo.org.slug,
            "role": uo.role,
            "repos": repos,
        })
    return result
