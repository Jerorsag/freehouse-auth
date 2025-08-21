"""
FastAPI dependencies for authentication and authorization with cookie support
"""
from typing import Annotated, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import Session

from app.core.security import verify_token
from app.core.cookies import get_token_from_cookie_or_header
from app.models.user import User
from app.services.auth_service import AuthService
from app.db.session import get_session

# HTTP Bearer security scheme (optional for cookie-based auth)
security = HTTPBearer(auto_error=False)


def get_auth_service(db: Session = Depends(get_session)) -> AuthService:
    """
    Dependency to get AuthService instance

    Args:
        db: Database session

    Returns:
        AuthService instance
    """
    return AuthService(db)


def get_current_user(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    auth_service: AuthService = Depends(get_auth_service)
) -> User:
    """
    Dependency to get current authenticated user from JWT token (cookie or header)

    Args:
        request: FastAPI Request object
        credentials: HTTP Bearer credentials (optional)
        auth_service: Auth service instance

    Returns:
        Current authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Get token from cookie or Authorization header
    token = get_token_from_cookie_or_header(request)

    if not token:
        raise credentials_exception

    # Get user from token
    user = auth_service.get_user_by_token(token)
    if not user:
        raise credentials_exception

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to get current active (non-deleted) user

    Args:
        current_user: Current user from token

    Returns:
        Current active user

    Raises:
        HTTPException: If user is inactive
    """
    if current_user.deleted_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


def get_optional_current_user(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    auth_service: AuthService = Depends(get_auth_service)
) -> Optional[User]:
    """
    Dependency to get current user (optional - doesn't raise exception if no token)

    Args:
        request: FastAPI Request object
        credentials: HTTP Bearer credentials (optional)
        auth_service: Auth service instance

    Returns:
        Current user or None if not authenticated
    """
    token = get_token_from_cookie_or_header(request)

    if not token:
        return None

    return auth_service.get_user_by_token(token)


def require_role(required_role_id: int):
    """
    Dependency factory to require specific role

    Args:
        required_role_id: Required role ID

    Returns:
        Dependency function that checks for role
    """
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role_id != required_role_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user

    return role_checker


def require_any_role(allowed_role_ids: list[int]):
    """
    Dependency factory to require any of the specified roles

    Args:
        allowed_role_ids: List of allowed role IDs

    Returns:
        Dependency function that checks for any of the roles
    """
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role_id not in allowed_role_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user

    return role_checker


class RoleChecker:
    """
    Class-based dependency for role checking with more flexibility
    """
    def __init__(self, allowed_roles: list[int]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role_id not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user


# Token validation dependency
def validate_access_token(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)]
) -> dict:
    """
    Dependency to validate access token without getting user

    Args:
        request: FastAPI Request object
        credentials: HTTP Bearer credentials (optional)

    Returns:
        Token payload

    Raises:
        HTTPException: If token is invalid
    """
    token = get_token_from_cookie_or_header(request)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(token, token_type="access")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


# Common role checkers (define based on your role IDs)
# Example usage:
# require_admin = require_role(1)  # Assuming admin role has ID 1
# require_user = require_any_role([1, 2])  # Admin or regular user
# allow_admin_or_manager = RoleChecker([1, 2])  # Class-based approach