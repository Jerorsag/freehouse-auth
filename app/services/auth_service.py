"""
Authentication service for user login, registration, and token management
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlmodel import Session, select

from app.core.security import (
    verify_password,
    get_password_hash,
    create_token_pair,
    verify_token,
    validate_password_strength
)
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core.config import settings


class AuthService:
    """Service class for handling authentication operations"""

    def __init__(self, db: Session):
        self.db = db

    def authenticate_user(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate a user with email and password

        Args:
            email: User's email
            password: Plain text password

        Returns:
            User object if authentication successful, None otherwise
        """
        # Get user by email
        statement = select(User).where(
            User.email == email,
            User.deleted_at.is_(None)  # Only active users
        )
        user = self.db.exec(statement).first()

        if not user:
            return None

        # Verify password
        if not verify_password(password, user.hashed_password):
            return None

        return user

    def create_user(
            self,
            name: str,
            email: str,
            password: str,
            lastname: Optional[str] = None,
            role_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create a new user account

        Args:
            name: User's first name
            email: User's email (must be unique)
            password: Plain text password
            lastname: User's last name (optional)
            role_id: Role ID (optional)

        Returns:
            Dictionary with user creation result
        """
        # Validate password strength
        password_validation = validate_password_strength(password)
        if not password_validation["is_valid"]:
            return {
                "success": False,
                "error": "Password does not meet requirements",
                "details": password_validation["errors"]
            }

        # Check if user already exists
        existing_user = self.db.exec(
            select(User).where(User.email == email)
        ).first()

        if existing_user:
            return {
                "success": False,
                "error": "User with this email already exists"
            }

        # Create new user
        hashed_password = get_password_hash(password)
        new_user = User(
            name=name,
            lastname=lastname,
            email=email,
            hashed_password=hashed_password,
            role_id=role_id,
            created_at=datetime.now(timezone.utc)
        )

        try:
            self.db.add(new_user)
            self.db.commit()
            self.db.refresh(new_user)

            return {
                "success": True,
                "user": new_user,
                "message": "User created successfully"
            }

        except Exception as e:
            self.db.rollback()
            return {
                "success": False,
                "error": f"Failed to create user: {str(e)}"
            }

    def login_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        Login a user and create token pair

        Args:
            email: User's email
            password: Plain text password

        Returns:
            Dictionary with login result and tokens
        """
        # Authenticate user
        user = self.authenticate_user(email, password)
        if not user:
            return {
                "success": False,
                "error": "Invalid credentials"
            }

        # Create token pair
        token_data = create_token_pair(user.id)

        # Store refresh token in database
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        refresh_token_record = RefreshToken(
            user_id=user.id,
            jti=token_data["jti"],
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc)
        )

        try:
            self.db.add(refresh_token_record)
            self.db.commit()

            return {
                "success": True,
                "access_token": token_data["access_token"],
                "refresh_token": token_data["refresh_token"],
                "token_type": token_data["token_type"],
                "expires_in": token_data["expires_in"],
                "user": {
                    "id": user.id,
                    "name": user.name,
                    "lastname": user.lastname,
                    "email": user.email,
                    "role_id": user.role_id
                }
            }

        except Exception as e:
            self.db.rollback()
            return {
                "success": False,
                "error": f"Failed to create session: {str(e)}"
            }

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Create new access token using refresh token

        Args:
            refresh_token: Valid refresh token

        Returns:
            Dictionary with new access token or error
        """
        # Verify refresh token
        payload = verify_token(refresh_token, token_type="refresh")
        if not payload:
            return {
                "success": False,
                "error": "Invalid or expired refresh token"
            }

        jti = payload.get("jti")
        user_id = payload.get("sub")

        if not jti or not user_id:
            return {
                "success": False,
                "error": "Invalid token payload"
            }

        # Check if refresh token exists and is not revoked
        statement = select(RefreshToken).where(
            RefreshToken.jti == jti,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc)
        )
        token_record = self.db.exec(statement).first()

        if not token_record:
            return {
                "success": False,
                "error": "Refresh token not found or revoked"
            }

        # Verify user still exists and is active
        user = self.db.get(User, int(user_id))
        if not user or user.deleted_at:
            return {
                "success": False,
                "error": "User not found or inactive"
            }

        # Create new access token
        from app.core.security import create_access_token
        new_access_token = create_access_token(subject=user_id)

        return {
            "success": True,
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    def logout_user(self, refresh_token: str) -> Dict[str, Any]:
        """
        Logout user by revoking refresh token

        Args:
            refresh_token: Refresh token to revoke

        Returns:
            Dictionary with logout result
        """
        payload = verify_token(refresh_token, token_type="refresh")
        if not payload:
            return {
                "success": False,
                "error": "Invalid refresh token"
            }

        jti = payload.get("jti")
        if not jti:
            return {
                "success": False,
                "error": "Invalid token payload"
            }

        # Revoke the refresh token
        statement = select(RefreshToken).where(RefreshToken.jti == jti)
        token_record = self.db.exec(statement).first()

        if token_record:
            token_record.revoked = True
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()

        return {
            "success": True,
            "message": "Logged out successfully"
        }

    def logout_all_devices(self, user_id: int) -> Dict[str, Any]:
        """
        Logout user from all devices by revoking all refresh tokens

        Args:
            user_id: User ID

        Returns:
            Dictionary with logout result
        """
        try:
            # Revoke all refresh tokens for the user
            statement = select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked == False
            )
            tokens = self.db.exec(statement).all()

            for token in tokens:
                token.revoked = True

            self.db.commit()

            return {
                "success": True,
                "message": f"Logged out from {len(tokens)} devices"
            }

        except Exception as e:
            self.db.rollback()
            return {
                "success": False,
                "error": f"Failed to logout from all devices: {str(e)}"
            }

    def get_user_by_token(self, access_token: str) -> Optional[User]:
        """
        Get user from access token

        Args:
            access_token: Valid access token

        Returns:
            User object or None
        """
        payload = verify_token(access_token, token_type="access")
        if not payload:
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        try:
            user = self.db.get(User, int(user_id))
            if user and not user.deleted_at:
                return user
        except (ValueError, TypeError):
            pass

        return None

    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired refresh tokens from database

        Returns:
            Number of tokens cleaned up
        """
        try:
            statement = select(RefreshToken).where(
                RefreshToken.expires_at < datetime.now(timezone.utc)
            )
            expired_tokens = self.db.exec(statement).all()

            count = len(expired_tokens)
            for token in expired_tokens:
                self.db.delete(token)

            self.db.commit()
            return count

        except Exception:
            self.db.rollback()
            return 0