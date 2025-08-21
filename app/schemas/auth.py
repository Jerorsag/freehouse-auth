"""
Pydantic schemas for authentication endpoints
"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator


class UserRegister(BaseModel):
    """Schema for user registration"""
    name: str = Field(..., min_length=1, max_length=100, description="User's first name")
    lastname: Optional[str] = Field(None, max_length=100, description="User's last name")
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, max_length=128, description="User's password")
    role_id: Optional[int] = Field(None, description="User's role ID")

    @validator('name')
    def name_must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()

    @validator('lastname')
    def lastname_strip(cls, v):
        if v:
            return v.strip()
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "name": "John",
                "lastname": "Doe",
                "email": "john.doe@example.com",
                "password": "SecurePassword123!",
                "role_id": 2
            }
        }


class UserLogin(BaseModel):
    """Schema for user login"""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")
    remember_me: bool = Field(default=False, description="Extend session duration")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "john.doe@example.com",
                "password": "SecurePassword123!",
                "remember_me": False
            }
        }


class TokenRefresh(BaseModel):
    """Schema for token refresh"""
    refresh_token: Optional[str] = Field(None, description="Refresh token (optional if using cookies)")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class TokenResponse(BaseModel):
    """Schema for token response"""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")
    user: 'UserResponse' = Field(..., description="User information")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 900,
                "user": {
                    "id": 1,
                    "name": "John",
                    "lastname": "Doe",
                    "email": "john.doe@example.com",
                    "role_id": 2
                }
            }
        }


class UserResponse(BaseModel):
    """Schema for user response"""
    id: int = Field(..., description="User ID")
    name: str = Field(..., description="User's first name")
    lastname: Optional[str] = Field(None, description="User's last name")
    email: str = Field(..., description="User's email address")
    role_id: Optional[int] = Field(None, description="User's role ID")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "John",
                "lastname": "Doe",
                "email": "john.doe@example.com",
                "role_id": 2
            }
        }


class RegisterResponse(BaseModel):
    """Schema for registration response"""
    message: str = Field(..., description="Success message")
    user: UserResponse = Field(..., description="Created user information")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "User registered successfully",
                "user": {
                    "id": 1,
                    "name": "John",
                    "lastname": "Doe",
                    "email": "john.doe@example.com",
                    "role_id": 2
                }
            }
        }


class LogoutResponse(BaseModel):
    """Schema for logout response"""
    message: str = Field(..., description="Logout message")
    logged_out_devices: Optional[int] = Field(None, description="Number of devices logged out")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Logged out successfully",
                "logged_out_devices": 1
            }
        }


class ErrorResponse(BaseModel):
    """Schema for error responses"""
    error: str = Field(..., description="Error message")
    details: Optional[list[str]] = Field(None, description="Additional error details")

    class Config:
        json_schema_extra = {
            "example": {
                "error": "Validation failed",
                "details": ["Password must contain at least one uppercase letter"]
            }
        }


class PasswordValidation(BaseModel):
    """Schema for password validation response"""
    is_valid: bool = Field(..., description="Whether password is valid")
    strength: str = Field(..., description="Password strength level")
    errors: list[str] = Field(default=[], description="Validation errors")

    class Config:
        json_schema_extra = {
            "example": {
                "is_valid": True,
                "strength": "strong",
                "errors": []
            }
        }


# Update forward reference
TokenResponse.model_rebuild()