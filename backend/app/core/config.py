import os
import sys
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

class Settings:
    PROJECT_NAME = "Secure Code Review RAG Agent"

    # Environment mode: "development" or "production"
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

    # JWT Configuration — centralized here, consumed by auth.py
    _DEV_FALLBACK_KEY = "INSECURE_DEV_ONLY_CHANGE_ME"
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "dummy")
    LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.0-flash-exp")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    VECTORSTORE_PATH = os.getenv("VECTORSTORE_PATH", "vectorstore")
    TOP_K = int(os.getenv("TOP_K", "4"))

    CONFIDENCE_HIGH = 0.75
    CONFIDENCE_MEDIUM = 0.45

settings = Settings()

# ── Security checks at startup ──────────────────────────────────────────────
if not settings.JWT_SECRET_KEY:
    if settings.ENVIRONMENT == "production":
        print("[FATAL] JWT_SECRET_KEY is not set. Refusing to start in production mode.")
        print("        Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\"")
        sys.exit(1)
    else:
        settings.JWT_SECRET_KEY = settings._DEV_FALLBACK_KEY
        print("[WARNING] JWT_SECRET_KEY not set — using insecure dev fallback.")
        print("          Set JWT_SECRET_KEY env var before deployment!")

if settings.ENVIRONMENT == "production" and settings.LLM_PROVIDER == "dummy":
    print("[WARNING] LLM_PROVIDER is 'dummy' in production mode. AI explanations will be unavailable.")

# Confirm key is loaded without leaking any key material
if settings.GEMINI_API_KEY:
    print("[INFO] Gemini API key loaded.")
else:
    print("[WARNING] No Gemini API key found. Using Dummy or Ollama mode.")
