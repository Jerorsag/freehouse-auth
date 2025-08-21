"""
Security utilities for password hashing and JWT tokens
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
import secrets
import uuid

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(
        subject: Union[str, Any],
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Create a JWT access token

    Args:
        subject: The subject (usually user ID) to encode in the token
        expires_delta: Token expiration time (default: from settings)
        additional_claims: Additional claims to include in the token

    Returns:
        Encoded JWT token
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
        "iat": datetime.now(timezone.utc)
    }

    if additional_claims:
        to_encode.update(additional_claims)

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(
        subject: Union[str, Any],
        jti: Optional[str] = None,
        expires_delta: Optional[timedelta] = None
) -> tuple[str, str]:
    """
    Create a JWT refresh token

    Args:
        subject: The subject (usually user ID) to encode in the token
        jti: JWT ID (unique identifier for the token)
        expires_delta: Token expiration time (default: from settings)

    Returns:
        Tuple of (encoded_jwt_token, jti)
    """
    if not jti:
        jti = str(uuid.uuid4())

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "type": "refresh",
        "jti": jti,
        "iat": datetime.now(timezone.utc)
    }

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt, jti


def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token

    Args:
        token: The JWT token to verify
        token_type: Expected token type ('access' or 'refresh')

    Returns:
        Decoded token payload or None if invalid
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        # Check token type
        if payload.get("type") != token_type:
            return None

        # Check expiration (JWT library handles this automatically, but we can double-check)
        exp = payload.get("exp")
        if exp is None:
            return None

        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            return None

        return payload

    except JWTError:
        return None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash

    Args:
        plain_password: The plain text password
        hashed_password: The hashed password to verify against

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt

    Args:
        password: The plain text password to hash

    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token

    Args:
        length: Token length (default: 32)

    Returns:
        Random token string
    """
    return secrets.token_urlsafe(length)


def create_token_pair(user_id: Union[str, int]) -> Dict[str, Any]:
    """
    Create both access and refresh tokens for a user

    Args:
        user_id: The user ID to create tokens for

    Returns:
        Dictionary with token information
    """
    access_token = create_access_token(subject=user_id)
    refresh_token, jti = create_refresh_token(subject=user_id)

    # Calculate expiration times
    access_expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # seconds
    refresh_expires_in = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_expires_in,
        "refresh_expires_in": refresh_expires_in,
        "jti": jti
    }


def extract_token_from_header(authorization: Optional[str]) -> Optional[str]:
    """
    Extract token from Authorization header

    Args:
        authorization: Authorization header value (e.g., "Bearer token123")

    Returns:
        Token string or None if invalid format
    """
    if not authorization:
        return None

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            return None
        return token
    except ValueError:
        return None


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength according to security requirements

    Args:
        password: The password to validate

    Returns:
        Dictionary with validation results
    """
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    if len(password) > 128:
        errors.append("Password must be less than 128 characters")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")

    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        errors.append("Password must contain at least one special character")

    # Additional security checks
    if password.lower() in ["password", "123456", "qwerty", "admin"]:
        errors.append("Password is too common")

    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "strength": "strong" if len(errors) == 0 else "weak"
    }


def get_user_id_from_token(token: str) -> Optional[int]:
    """
    Extract user ID from a JWT token

    Args:
        token: JWT token

    Returns:
        User ID or None if invalid token
    """
    payload = verify_token(token)
    if payload:
        try:
            return int(payload.get("sub"))
        except (ValueError, TypeError):
            return None
    return None


def is_token_expired(token: str) -> bool:
    """
    Check if a token is expired

    Args:
        token: JWT token to check

    Returns:
        True if expired, False if valid
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": False}  # Don't raise exception on expired token
        )
        exp = payload.get("exp")
        if exp is None:
            return True
        return datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc)
    except JWTError:
        return True


def revoke_token_family(user_id: int) -> str:
    """
    Generate a new token family ID to invalidate all existing refresh tokens
    This is useful for logout from all devices

    Args:
        user_id: User ID

    Returns:
        New token family ID
    """
    return f"{user_id}_{secrets.token_urlsafe(16)}"