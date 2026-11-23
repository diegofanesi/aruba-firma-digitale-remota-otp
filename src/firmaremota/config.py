"""User settings (INI file, no secrets) and XDG paths."""

from __future__ import annotations

import configparser
import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path

APP_NAME = "firma-remota"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / APP_NAME


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / APP_NAME


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / APP_NAME


def config_path() -> Path:
    return config_dir() / "config.ini"


@dataclass
class Settings:
    user: str = ""
    domain: str = ""  # ARSS typeOtpAuth
    cert_id: str = "AS0"
    type_hsm: str = "COSIGN"
    signer_name: str = ""  # certificate holder, written in the visible stamp

    @property
    def complete(self) -> bool:
        return bool(self.user and self.domain)


def load(path: Path | None = None) -> Settings:
    path = path or config_path()
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path, encoding="utf-8")
    section = parser["account"] if parser.has_section("account") else {}
    known = {f.name for f in fields(Settings)}
    return Settings(**{k: v for k, v in section.items() if k in known})


def save(settings: Settings, path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parser = configparser.ConfigParser(interpolation=None)
    parser["account"] = {k: str(v) for k, v in asdict(settings).items()}
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        parser.write(f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return path


@dataclass
class State:
    """Things the app remembers between runs (not settings)."""

    auth_failures: int = 0  # consecutive refused logins/OTPs; reset by any success


def state_path() -> Path:
    return state_dir() / "state.json"


def load_state(path: Path | None = None) -> State:
    path = path or state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return State()
    known = {f.name for f in fields(State)}
    return State(**{k: v for k, v in data.items() if k in known})


def save_state(state: State, path: Path | None = None) -> None:
    path = path or state_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(asdict(state), f)
    os.replace(tmp, path)
