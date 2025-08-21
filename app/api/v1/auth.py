"""
Authentication endpoints for user registration, login, and token management
"""
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session

from app.core.dependencies import get_auth_service, get_current_active_user
from app.core.cookies import (
    CookieManager,
    get_refresh_token_from_cookie_or_body,
    get_token_from_cookie_or_header
)
from app.services.auth_service import AuthService
from app.models.user import User
from app.schemas.auth import (
    UserRegister,
    UserLogin,
    TokenRefresh,
    TokenResponse,
    UserResponse,
    RegisterResponse,
    LogoutResponse,
    ErrorResponse,
    PasswordValidation
)
from app.core.security import validate_password_strength
from app.db.session import get_session

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Registration failed"},
        422: {"model": ErrorResponse, "description": "Validation error"}
    }
)
async def register(
        user_data: UserRegister,
        auth_service: AuthService = Depends(get_auth_service)
) -> RegisterResponse:
    """
    Register a new user account

    - **name**: User's first name (required)
    - **lastname**: User's last name (optional)
    - **email**: Valid email address (required, unique)
    - **password**: Secure password (required, min 8 characters)
    - **role_id**: Role ID (optional)

    Returns user information without sensitive data.
    """
    # Create user
    result = auth_service.create_user(
        name=user_data.name,
        lastname=user_data.lastname,
        email=user_data.email,
        password=user_data.password,
        role_id=user_data.role_id
    )

    if not result["success"]:
        if "already exists" in result["error"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )
        elif "Password does not meet requirements" in result["error"]:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=result["error"],
                headers={"X-Error-Details": str(result.get("details", []))}
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )

    # Convert user model to response schema
    user_response = UserResponse(
        id=result["user"].id,
        name=result["user"].name,
        lastname=result["user"].lastname,
        email=result["user"].email,
        role_id=result["user"].role_id
    )

    return RegisterResponse(
        message="User registered successfully",
        user=user_response
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        422: {"model": ErrorResponse, "description": "Validation error"}
    }
)
async def login(
        response: Response,
        user_credentials: UserLogin,
        auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    """
    Login with email and password

    - **email**: User's email address
    - **password**: User's password
    - **remember_me**: Extend session duration (optional)

    Returns access token and sets secure HTTP-only cookies.
    """
    # Authenticate and login user
    result = auth_service.login_user(
        email=user_credentials.email,
        password=user_credentials.password
    )

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result["error"],
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Set secure cookies
    CookieManager.set_auth_cookies(
        response=response,
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        remember_me=user_credentials.remember_me
    )

    # Convert user data to response schema
    user_response = UserResponse(
        id=result["user"]["id"],
        name=result["user"]["name"],
        lastname=result["user"]["lastname"],
        email=result["user"]["email"],
        role_id=result["user"]["role_id"]
    )

    return TokenResponse(
        access_token=result["access_token"],
        token_type=result["token_type"],
        expires_in=result["expires_in"],
        user=user_response
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid refresh token"},
        403: {"model": ErrorResponse, "description": "Token revoked or expired"}
    }
)
async def refresh_token(
        request: Request,
        response: Response,
        token_data: TokenRefresh,
        auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    """
    Refresh access token using refresh token

    - **refresh_token**: Valid refresh token (optional if using cookies)

    Returns new access token and updates cookies.
    """
    # Get refresh token from cookie or request body
    refresh_token = get_refresh_token_from_cookie_or_body(
        request=request,
        refresh_token_body=token_data.refresh_token
    )

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Refresh the access token
    result = auth_service.refresh_access_token(refresh_token)

    if not result["success"]:
        if "not found or revoked" in result["error"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=result["error"]
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result["error"],
                headers={"WWW-Authenticate": "Bearer"}
            )

    # Update access token cookie
    CookieManager.update_access_token_cookie(
        response=response,
        access_token=result["access_token"]
    )

    # Get user info for response (we can get this from the token)
    from app.core.security import verify_token
    payload = verify_token(result["access_token"], token_type="access")
    user_id = int(payload["sub"])

    # Get user from database
    db: Session = next(get_session())
    user = db.get(User, user_id)

    user_response = UserResponse(
        id=user.id,
        name=user.name,
        lastname=user.lastname,
        email=user.email,
        role_id=user.role_id
    )

    return TokenResponse(
        access_token=result["access_token"],
        token_type=result["token_type"],
        expires_in=result["expires_in"],
        user=user_response
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"}
    }
)
async def logout(
        request: Request,
        response: Response,
        auth_service: AuthService = Depends(get_auth_service)
) -> LogoutResponse:
    """
    Logout current user and revoke refresh token

    Clears HTTP-only cookies and revokes the current refresh token.
    """
    # Get refresh token from cookie
    refresh_token = CookieManager.get_refresh_token_from_cookie(request)

    if refresh_token:
        # Revoke the refresh token
        result = auth_service.logout_user(refresh_token)

        # Clear authentication cookies
        CookieManager.clear_auth_cookies(response)

        return LogoutResponse(
            message=result.get("message", "Logged out successfully"),
            logged_out_devices=1
        )
    else:
        # No refresh token found, but clear cookies anyway
        CookieManager.clear_auth_cookies(response)
        return LogoutResponse(
            message="Logged out successfully",
            logged_out_devices=0
        )


@router.post(
    "/logout-all",
    response_model=LogoutResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"}
    }
)
async def logout_all_devices(
        response: Response,
        current_user: User = Depends(get_current_active_user),
        auth_service: AuthService = Depends(get_auth_service)
) -> LogoutResponse:
    """
    Logout from all devices

    Revokes all refresh tokens for the current user.
    Requires authentication.
    """
    # Logout from all devices
    result = auth_service.logout_all_devices(current_user.id)

    # Clear cookies for current session
    CookieManager.clear_auth_cookies(response)

    if result["success"]:
        return LogoutResponse(
            message=result["message"],
            logged_out_devices=result["message"].split(" ")[3] if "devices" in result["message"] else None
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"]
        )


@router.get(
    "/me",
    response_model=UserResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"}
    }
)
async def get_current_user_info(
        current_user: User = Depends(get_current_active_user)
) -> UserResponse:
    """
    Get current user information

    Returns information about the currently authenticated user.
    Requires valid access token (cookie or Authorization header).
    """
    return UserResponse(
        id=current_user.id,
        name=current_user.name,
        lastname=current_user.lastname,
        email=current_user.email,
        role_id=current_user.role_id
    )


@router.post(
    "/validate-password",
    response_model=PasswordValidation,
    status_code=status.HTTP_200_OK
)
async def validate_password(
        password: str
) -> PasswordValidation:
    """
    Validate password strength

    - **password**: Password to validate

    Returns validation results with strength assessment and any errors.
    """
    validation = validate_password_strength(password)

    return PasswordValidation(
        is_valid=validation["is_valid"],
        strength=validation["strength"],
        errors=validation["errors"]
    )


@router.get(
    "/status",
    response_model=dict,
    include_in_schema=False
)
async def auth_status(
        request: Request,
        auth_service: AuthService = Depends(get_auth_service)
) -> dict:
    """
    Check authentication status (internal endpoint)

    Returns authentication status and user info if authenticated.
    """
    token = get_token_from_cookie_or_header(request)

    if not token:
        return {
            "authenticated": False,
            "user": None
        }

    user = auth_service.get_user_by_token(token)

    if user:
        return {
            "authenticated": True,
            "user": {
                "id": user.id,
                "name": user.name,
                "lastname": user.lastname,
                "email": user.email,
                "role_id": user.role_id
            }
        }
    else:
        return {
            "authenticated": False,
            "user": None
        }