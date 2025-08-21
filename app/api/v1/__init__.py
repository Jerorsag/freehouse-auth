"""
API v1 router configuration
"""
from fastapi import APIRouter

from app.api.v1.auth import router as auth_router

# Create main API v1 router
api_router = APIRouter(prefix="/api/v1")

# Include auth routes
api_router.include_router(auth_router)

# You can add more routers here as you expand your API
# api_router.include_router(users_router)
# api_router.include_router(products_router)
# etc.