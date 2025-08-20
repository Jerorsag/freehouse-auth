from sqlmodel import SQLModel

# Importar todos los modelos aquí para que Alembic los detecte
from app.models.role import Role  # noqa
from app.models.user import User  # noqa
from app.models.refresh_token import RefreshToken  # noqa

# Exportar metadata para Alembic
metadata = SQLModel.metadata