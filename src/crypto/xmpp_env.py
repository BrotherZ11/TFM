import os
from pathlib import Path


_ENV_LOADED = False
_ROLE_DEFAULTS = {
    "EMISOR": "emisor",
    "RECEPTOR": "receptor",
    "ADMIN": "admin",
}


def load_repo_env() -> None:
    global _ENV_LOADED
    if _ENV_LOADED:
        return

    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            os.environ.setdefault(key, value)

    _ENV_LOADED = True


def get_env(name: str, default: str) -> str:
    load_repo_env()
    return os.getenv(name, default)


def get_xmpp_jid(role: str) -> str:
    load_repo_env()
    role_name = role.upper()
    default_user = _ROLE_DEFAULTS.get(role_name, role.lower())
    user = os.getenv(f"XMPP_{role_name}_USER", default_user)
    if "@" in user:
        return user
    domain = os.getenv("XMPP_DOMAIN", "localhost")
    return f"{user}@{domain}"


def get_xmpp_password(role: str, default: str = "123") -> str:
    load_repo_env()
    return os.getenv(f"XMPP_{role.upper()}_PASS", default)


def get_xmpp_host() -> str:
    return get_env("XMPP_HOST", "127.0.0.1")


def get_xmpp_port() -> int:
    return int(get_env("XMPP_PORT", "5222"))


def get_subject_dn(role: str, organization: str = "UMA", country: str = "ES") -> str:
    jid = get_xmpp_jid(role)
    return f"CN={jid},O={organization},C={country}"
