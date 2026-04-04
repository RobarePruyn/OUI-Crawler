"""Authentication — basic auth with bcrypt, abstracted for future SAML/SSO."""

import hashlib
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import get_db
from .db_models import User, Venue, user_venue


def hash_password(plain: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260000)
    return f"{salt}${h.hex()}"


def verify_password(plain: str, hashed: str) -> bool:
    try:
        salt, digest = hashed.split("$", 1)
        h = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260000)
        return secrets.compare_digest(h.hex(), digest)
    except (ValueError, AttributeError):
        return False


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.password_hash):
        return user
    return None


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency — the single auth gate.

    Swap this implementation for SAML/SSO later without changing route code.
    Currently reads user_id from a signed session cookie.
    """
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    return user


def get_user_venues(db: Session, user: User) -> list:
    """Return venues accessible to this user."""
    if user.role == "super_admin":
        return db.query(Venue).order_by(Venue.id).all()
    return db.query(Venue).join(user_venue).filter(user_venue.c.user_id == user.id).order_by(Venue.id).all()


def require_venue_access(user: User, venue_id: int, db: Session):
    """Raise 403 if a site_admin doesn't have access to this venue."""
    if user.role == "super_admin":
        return
    has = db.query(user_venue).filter(
        user_venue.c.user_id == user.id,
        user_venue.c.venue_id == venue_id,
    ).first()
    if not has:
        raise HTTPException(status_code=403, detail="No access to this venue")


def check_venue_access(request: Request, db: Session = Depends(get_db)):
    """Middleware-style check: if the route has a venue_id path param, enforce access."""
    user_id = request.session.get("user_id")
    if user_id is None:
        return  # auth gate will catch this
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role == "super_admin":
        return
    # Extract venue_id from path params
    venue_id = request.path_params.get("venue_id")
    if venue_id is not None:
        require_venue_access(user, int(venue_id), db)


def ensure_default_admin(db: Session) -> Optional[str]:
    """Create default admin if no users exist. Returns password if created."""
    if db.query(User).count() > 0:
        return None
    password = secrets.token_urlsafe(16)
    admin = User(
        username="admin",
        password_hash=hash_password(password),
        role="super_admin",
    )
    db.add(admin)
    db.commit()
    return password
