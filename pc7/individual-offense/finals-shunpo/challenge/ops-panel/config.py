import os


class Config:
    SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-unsafe-secret-change-me")
    SESSION_COOKIE_NAME = "ops_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    OPS_ADMIN_USER = os.environ.get("OPS_ADMIN_USER", "opsadmin")
    OPS_ADMIN_PASS = os.environ.get("OPS_ADMIN_PASS", "change-me")

    ROUTE_KEY = os.environ.get("ROUTE_KEY", "route-key-not-set")
    INTERNAL_SIGNING_KEY = os.environ.get("INTERNAL_SIGNING_KEY", "internal-signing-key-not-set")
    BRIDGE_TICKET = os.environ.get("BRIDGE_TICKET", "PCCC{SHN-A4-a842ec49}")
    FINAL_TOKEN = os.environ.get("FINAL_TOKEN", "PCCC{SHN-A5-4e1d9a7c}")

    INTERNAL_HOST = os.environ.get("INTERNAL_HOST", "127.0.0.1")
    INTERNAL_PORT = int(os.environ.get("INTERNAL_PORT", os.environ.get("PORT", "8080")))

    TRUSTED_DASHBOARD_HOSTS = {
        host.strip()
        for host in os.environ.get("TRUSTED_DASHBOARD_HOSTS", "sp-dashboard.ninja,dashboard").split(",")
        if host.strip()
    }

    COAP_BRIDGE_HOST = os.environ.get("COAP_BRIDGE_HOST", "sp-coap.ninja").strip()
    COAP_BRIDGE_PORT = int(os.environ.get("COAP_BRIDGE_PORT", "5683"))
    COAP_SHARED_KEY = os.environ.get("COAP_SHARED_KEY", "replace-me")
    DEFAULT_DETAIL_MODE = os.environ.get("DEFAULT_DETAIL_MODE", "standard")

    LOGIN_BANNER = os.environ.get(
    "LOGIN_BANNER",
    "Night Crossing\nConsole"
    )
