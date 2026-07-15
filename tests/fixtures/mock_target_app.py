"""Minimal vulnerable FastAPI application for testing STRYX.

This app intentionally contains security vulnerabilities for STRYX to detect:
- IDOR (Insecure Direct Object Reference)
- Reflected input (XSS / injection)
- Unauthenticated admin panel
- Missing auth on API endpoints
- CORS misconfiguration

DO NOT use this in production. For testing STRYX only.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="STRYX Mock Vulnerable App")

# Simulated user database
USERS_DB = {
    "1": {"id": "1", "name": "Alice", "email": "alice@example.com", "password": "secret123", "role": "user"},
    "2": {"id": "2", "name": "Bob", "email": "bob@example.com", "password": "password456", "role": "user"},
    "3": {"id": "3", "name": "Admin", "email": "admin@example.com", "password": "admin", "role": "admin"},
}

# Simulated orders
ORDERS_DB = {
    "1": {"id": "1", "user_id": "1", "item": "Laptop", "amount": 999.99},
    "2": {"id": "2", "user_id": "2", "item": "Phone", "amount": 599.99},
    "3": {"id": "3", "user_id": "1", "item": "Tablet", "amount": 399.99},
}


@app.get("/", response_class=HTMLResponse)
async def index():
    """Basic landing page."""
    return """
    <html>
    <head><title>STRYX Test App</title></head>
    <body>
        <h1>STRYX Mock Vulnerable Application</h1>
        <p>This app is for testing STRYX DAST scanner.</p>
        <ul>
            <li><a href="/api/users/1">User API (IDOR vulnerable)</a></li>
            <li><a href="/api/orders/1">Orders API (IDOR vulnerable)</a></li>
            <li><a href="/admin">Admin Panel (no auth)</a></li>
            <li><a href="/search?q=test">Search (reflected input)</a></li>
            <li><a href="/login">Login</a></li>
        </ul>
        <script src="/static/app.js"></script>
    </body>
    </html>
    """


@app.get("/robots.txt")
async def robots():
    """Robots.txt with some hidden paths."""
    return Response(
        content="User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nDisallow: /debug",
        media_type="text/plain",
    )


@app.get("/api/users/{user_id}")
async def get_user(user_id: str):
    """IDOR-vulnerable user endpoint -- no auth check."""
    user = USERS_DB.get(user_id)
    if user:
        # Returns all fields including password -- intentional vulnerability
        return user
    return JSONResponse(status_code=404, content={"error": "User not found"})


@app.get("/api/orders/{order_id}")
async def get_order(order_id: str):
    """IDOR-vulnerable order endpoint -- no auth check."""
    order = ORDERS_DB.get(order_id)
    if order:
        return order
    return JSONResponse(status_code=404, content={"error": "Order not found"})


@app.get("/api/users")
async def list_users():
    """List all users -- no auth required."""
    return list(USERS_DB.values())


@app.post("/api/users")
async def create_user(request: Request):
    """Create user -- no validation."""
    data = await request.json()
    return JSONResponse(status_code=201, content={"message": "User created", "data": data})


@app.get("/search")
async def search(q: str = ""):
    """Reflected input -- vulnerable to XSS/injection."""
    return HTMLResponse(
        content=f"""
        <html>
        <body>
            <h1>Search Results</h1>
            <p>Search query: {q}</p>
            <p>No results found for: {q}</p>
        </body>
        </html>
        """,
    )


@app.get("/admin")
async def admin_panel():
    """Admin panel -- no authentication required."""
    return HTMLResponse(
        content="""
        <html>
        <body>
            <h1>Admin Panel</h1>
            <p>Welcome, Administrator</p>
            <ul>
                <li><a href="/api/admin/users">Manage Users</a></li>
                <li><a href="/api/admin/config">System Config</a></li>
                <li><a href="/api/admin/logs">System Logs</a></li>
            </ul>
        </body>
        </html>
        """,
    )


@app.get("/api/admin/users")
async def admin_list_users():
    """Admin user management -- no auth."""
    return list(USERS_DB.values())


@app.get("/api/admin/config")
async def admin_config():
    """Admin config endpoint -- no auth, returns sensitive data."""
    return {
        "database_host": "localhost",
        "database_port": 5432,
        "database_password": "super_secret_password",
        "api_key": "sk-1234567890abcdef",
        "jwt_secret": "my-super-secret-jwt-key",
    }


@app.get("/api/admin/logs")
async def admin_logs():
    """Admin logs endpoint -- no auth."""
    return {
        "logs": [
            "2026-01-01: User admin logged in from 192.168.1.100",
            "2026-01-02: Failed login attempt from 10.0.0.5",
            "2026-01-03: Database backup completed",
        ]
    }


@app.post("/login")
async def login(request: Request):
    """Login endpoint -- weak validation."""
    try:
        data = await request.json()
        username = data.get("username", "")
        password = data.get("password", "")

        # Check against any user (intentionally weak)
        for user in USERS_DB.values():
            if user["name"].lower() == username.lower():
                return {
                    "token": f"jwt-token-for-{user['id']}",
                    "user": user["name"],
                    "role": user["role"],
                }

        return JSONResponse(status_code=401, content={"error": "Invalid credentials"})
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid request"})


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/internal")
async def internal_api():
    """Internal API -- should not be exposed."""
    return {"secret": "internal-data", "version": "1.0.0"}


@app.get("/debug")
async def debug():
    """Debug endpoint -- should not be in production."""
    return {
        "debug": True,
        "env": "development",
        "database_url": "postgresql://admin:password@localhost:5432/mydb",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
