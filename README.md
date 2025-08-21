# 🚀 `freehouse-auth`

Bienvenido al backend de la API de Freehouse. Esta API está construida con FastAPI, SQLModel y PostgreSQL para gestionar la autenticación de usuarios.

## Tabla de Contenidos

  - [Requisitos Previos](https://www.google.com/search?q=%23requisitos-previos)
  - [1. Configuración Inicial](https://www.google.com/search?q=%231-configuraci%C3%B3n-inicial)
  - [2. Variables de Entorno](https://www.google.com/search?q=%232-variables-de-entorno)
  - [3. Migraciones de la Base de Datos](https://www.google.com/search?q=%233-migraciones-de-la-base-de-datos)
  - [4. Ejecutar el Servidor](https://www.google.com/search?q=%234-ejecutar-el-servidor)
  - [Documentación de la API](https://www.google.com/search?q=%23documentaci%C3%B3n-de-la-api)

-----

## Requisitos Previos

Asegúrate de tener instalados los siguientes programas en tu sistema:

  - **Python 3.11** (Versión recomendada para compatibilidad).
  - **PostgreSQL** (Versión 14 o superior).
  - **`git`** (Para clonar el repositorio).

-----

## 1\. Configuración Inicial

1.  **Clona el repositorio** en tu máquina local:

    ```bash
    git clone https://github.com/tu-usuario/freehouse-backend.git
    cd freehouse-backend
    ```

    *(Recuerda reemplazar la URL con la de tu repositorio.)*

2.  **Crea y activa el entorno virtual** usando Python 3.11 para una compatibilidad garantizada:

    ```bash
    py -3.11 -m venv .venv
    .\.venv\Scripts\activate
    ```

3.  **Instala las dependencias del proyecto** desde el archivo `requirements.txt`:

    ```bash
    pip install -r requirements.txt
    ```

-----

## 2\. Variables de Entorno

El proyecto necesita un archivo `.env` para la configuración de la base de datos y la seguridad.

1.  Crea un nuevo archivo en la raíz del proyecto llamado **`.env`**.

2.  Copia y pega el siguiente contenido, reemplazando los valores con tu propia configuración:

    ```ini
    # Configuración de la Base de Datos
    DB_USER=tu_usuario_postgres
    DB_PASS=tu_contraseña
    DB_HOST=127.0.0.1
    DB_PORT=5432
    DB_NAME=freehouse_db

    # Configuración de la Seguridad (JWT)
    JWT_SECRET_KEY="tu_llave_secreta_super_segura"
    JWT_ALGORITHM="HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES=30
    ```

-----

## 3\. Migraciones de la Base de Datos

Antes de ejecutar la API, debes asegurarte de que la base de datos `freehouse_db` esté creada y de que todas las tablas y datos iniciales (roles) estén en su lugar.

1.  **Crea la base de datos `freehouse_db`** en tu servidor de PostgreSQL. Puedes usar `psql` o `pgAdmin`.

2.  **Aplica las migraciones de Alembic** para crear las tablas y poblar la base de datos.

    ```bash
    alembic upgrade head
    ```

-----

## 4\. Ejecutar el Servidor

Una vez que todas las configuraciones estén listas, puedes iniciar el servidor:

```bash
uvicorn app.main:app --reload
```

El servidor estará disponible en `http://127.0.0.1:8000`.

-----

## Documentación de la API

Puedes acceder a la documentación interactiva de la API para probar tus endpoints de autenticación:

  - **Swagger UI:** `http://127.0.0.1:8000/docs`
  - **ReDoc:** `http://127.0.0.1:8000/redoc`
