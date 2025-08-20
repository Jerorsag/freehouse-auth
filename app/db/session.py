from sqlmodel import create_engine, Session
from app.core.config import settings

# Crear engine
engine = create_engine(
    settings.DATABASE_URL,
    echo=True,  # Para ver las queries SQL en desarrollo
    pool_pre_ping=True,  # Verificar conexiones antes de usarlas
    pool_recycle=300  # Reciclar conexiones cada 5 minutos
)


def get_session():
    """Dependency para obtener sesión de base de datos"""
    with Session(engine) as session:
        yield session