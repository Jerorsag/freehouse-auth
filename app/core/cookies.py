"""
Cookie utilities for secure authentication
"""
from typing import Optional
from fastapi import Response, Request
from app.core.config import settings


class CookieManager:
    """Manager for handling secure authentication cookies"""

    # Cookie names
    ACCESS_TOKEN_COOKIE = "access_token"
    REFRESH_TOKEN_COOKIE = "refresh_token"

    @staticmethod
    def set_auth_cookies(
            response: Response,
            access_token: str,
            refresh_token: str,
            remember_me: bool = False
    ) -> None:
        """
        Set secure authentication cookies

        Args:
            response: FastAPI Response object
            access_token: JWT access token
            refresh_token: JWT refresh token
            remember_me: Whether to extend cookie lifetime
        """
        # Access token cookie (shorter expiration)
        access_max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # seconds

        response.set_cookie(
            key=CookieManager.ACCESS_TOKEN_COOKIE,
            value=access_token,
            max_age=access_max_age,
            httponly=True,  # Prevent XSS attacks
            secure=True,  # HTTPS only in production
            samesite="strict",  # CSRF protection
            path="/",
        )

        # Refresh token cookie (longer expiration)
        refresh_max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds
        if remember_me:
            refresh_max_age = refresh_max_age * 2  # Double the time for remember me

        response.set_cookie(
            key=CookieManager.REFRESH_TOKEN_COOKIE,
            value=refresh_token,
            max_age=refresh_max_age,
            httponly=True,  # Prevent XSS attacks
            secure=True,  # HTTPS only in production
            samesite="strict",  # CSRF protection
            path="/",
        )

    @staticmethod
    def clear_auth_cookies(response: Response) -> None:
        """
        Clear authentication cookies

        Args:
            response: FastAPI Response object
        """
        response.delete_cookie(
            key=CookieManager.ACCESS_TOKEN_COOKIE,
            path="/",
            httponly=True,
            secure=True,
            samesite="strict"
        )

        response.delete_cookie(
            key=CookieManager.REFRESH_TOKEN_COOKIE,
            path="/",
            httponly=True,
            secure=True,
            samesite="strict"
        )

    @staticmethod
    def get_access_token_from_cookie(request: Request) -> Optional[str]:
        """
        Get access token from cookie

        Args:
            request: FastAPI Request object

        Returns:
            Access token or None
        """
        return request.cookies.get(CookieManager.ACCESS_TOKEN_COOKIE)

    @staticmethod
    def get_refresh_token_from_cookie(request: Request) -> Optional[str]:
        """
        Get refresh token from cookie

        Args:
            request: FastAPI Request object

        Returns:
            Refresh token or None
        """
        return request.cookies.get(CookieManager.REFRESH_TOKEN_COOKIE)

    @staticmethod
    def update_access_token_cookie(
            response: Response,
            access_token: str
    ) -> None:
        """
        Update only the access token cookie (for token refresh)

        Args:
            response: FastAPI Response object
            access_token: New JWT access token
        """
        access_max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        response.set_cookie(
            key=CookieManager.ACCESS_TOKEN_COOKIE,
            value=access_token,
            max_age=access_max_age,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
        )


def get_token_from_cookie_or_header(request: Request) -> Optional[str]:
    """
    Get access token from cookie first, fallback to Authorization header

    Args:
        request: FastAPI Request object

    Returns:
        Access token or None
    """
    # Try cookie first
    token = CookieManager.get_access_token_from_cookie(request)

    # Fallback to Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ")[1]

    return token


def get_refresh_token_from_cookie_or_body(
        request: Request,
        refresh_token_body: Optional[str] = None
) -> Optional[str]:
    """
    Get refresh token from cookie first, fallback to request body

    Args:
        request: FastAPI Request object
        refresh_token_body: Refresh token from request body

    Returns:
        Refresh token or None
    """
    # Try cookie first
    token = CookieManager.get_refresh_token_from_cookie(request)

    # Fallback to request body
    if not token and refresh_token_body:
        token = refresh_token_body

    return token