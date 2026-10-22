#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wpbackup - Sauvegarde / restauration de sites WordPress (orienté RGPD)
======================================================================

Fonctionnalités
  * Plusieurs profils de sauvegarde (un fichier JSON par profil)
  * 1..n bases MySQL/MariaDB + 1..n répertoires (avec exclusions)
  * Chiffrement optionnel AES-256-GCM (clé dérivée du mot de passe par scrypt)
  * Destinations : local, NFS, S3 (AWS ou compatible S3), SMB/CIFS
  * Rétention par profil, appliquée APRÈS une sauvegarde réussie
  * Notification SMTP (succès / échec / sauvegardes expirées supprimées)
  * Restauration à une date donnée (rollback) avec sauvegarde de sécurité
  * Planification par profil (intervalle) via `run-due` + cron/systemd
  * Journal d'audit (RGPD, art. 5-2 « responsabilité »)

Commandes (python3 wpbackup.py --help pour le détail)
  create-profile [NOM]      Assistant de création d'un scénario de sauvegarde
  list-profiles             Liste les profils
  show-profile NOM          Affiche un profil (secrets masqués)
  run NOM [NOM…] | --all    Exécution manuelle d'un, de plusieurs ou de tous les profils
  run-due                   Lance les profils dont l'échéance est atteinte (cron/systemd)
  list-backups NOM          Liste les sauvegardes disponibles
  restore NOM [--date …]    Restaure (BDD et/ou fichiers) à une date donnée
  test-mail NOM             Envoie un mail de test
  doctor                    Vérifie les dépendances
  install-scheduler         Installe la planification (cron.d ou timer systemd)

Variables d'environnement (facultatives)
  WPBACKUP_CONFIG_DIR (/etc/wpbackup)  WPBACKUP_STATE_DIR (/var/lib/wpbackup)
  WPBACKUP_LOG_DIR (/var/log/wpbackup) WPBACKUP_WORK_DIR (/var/tmp/wpbackup)

Secrets dans les profils : valeur en clair, "env:NOM_VARIABLE" ou "file:/chemin/secret".
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import email.utils
import fcntl
import fnmatch
import getpass
import hashlib
import io
import json
import logging
import logging.handlers
import os
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0.0"

CONFIG_DIR = Path(os.environ.get("WPBACKUP_CONFIG_DIR", "/etc/wpbackup"))
PROFILES_DIR = CONFIG_DIR / "profiles"
SECRETS_DIR = CONFIG_DIR / "secrets"
STATE_DIR = Path(os.environ.get("WPBACKUP_STATE_DIR", "/var/lib/wpbackup"))
LOG_DIR = Path(os.environ.get("WPBACKUP_LOG_DIR", "/var/log/wpbackup"))
DEFAULT_WORK_DIR = os.environ.get("WPBACKUP_WORK_DIR", "/var/tmp/wpbackup")

PROFILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
DB_NAME_RE = re.compile(r"^[\w$\-]+$")
LABEL_RE = re.compile(r"^[\w.\-]+$")
BACKUP_RE = re.compile(r"^(?P<profile>.+)_(?P<ts>\d{8}-\d{6})\.tar\.gz(?P<enc>\.enc)?$")
TS_FORMAT = "%Y%m%d-%H%M%S"
DATE_FMT = "%d/%m/%Y %H:%M:%S"

log = logging.getLogger("wpbackup")


class ConfigError(Exception):
    pass


class BackupError(Exception):
    pass


class ProfileBusy(Exception):
    pass


class UserCancelled(Exception):
    pass


# =============================================================================
# Secrets, journalisation, audit
# =============================================================================
_SECRETS: set = set()


def register_secret(value: Optional[str]) -> None:
    if value and len(value) >= 4:
        _SECRETS.add(value)


def scrub(text: Any) -> str:
    """Masque tous les secrets connus dans un texte (logs, mails, erreurs)."""
    text = str(text)
    for s in sorted(_SECRETS, key=len, reverse=True):
        text = text.replace(s, "***")
    return text


def resolve_secret(value: Optional[str]) -> Optional[str]:
    """Valeur en clair, 'env:VAR' ou 'file:/chemin'."""
    if value is None:
        return None
    value = str(value)
    if value.startswith("env:"):
        v = os.environ.get(value[4:])
        if v is None:
            raise ConfigError(f"Variable d'environnement absente : {value[4:]}")
    elif value.startswith("file:"):
        try:
            v = Path(value[5:]).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as e:
            raise ConfigError(f"Fichier secret illisible ({value[5:]}) : {e}")
    else:
        v = value
    register_secret(v)
    return v


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = scrub(record.getMessage())
        record.args = ()
        return True


def setup_logging(verbose: bool = False) -> None:
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    log.addFilter(ScrubFilter())
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stderr)
    if verbose:
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO if sys.stderr.isatty() else logging.WARNING)
    console.setFormatter(fmt)
    log.addHandler(console)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(LOG_DIR, 0o750)
        fh = logging.handlers.RotatingFileHandler(
            LOG_DIR / "wpbackup.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError as e:
        log.warning("Journal fichier indisponible (%s) : journalisation console uniquement", e)


def audit(event: str, **fields: Any) -> None:
    """Journal d'audit JSON-lines : qui, quand, quoi (jamais de données personnelles)."""
    rec = {
        "ts": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "event": event,
        "host": socket.gethostname(),
        "uid": os.getuid(),
    }
    rec.update(fields)
    try:
        path = LOG_DIR / "audit.log"
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        os.chmod(path, 0o600)
    except OSError as e:
        log.warning("Écriture du journal d'audit impossible : %s", e)


# =============================================================================
# Utilitaires
# =============================================================================
def human_size(n: float) -> str:
    n = float(n)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or unit == "To":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} h {m:02d} min {s:02d} s"
    if m:
        return f"{m} min {s:02d} s"
    return f"{s} s"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_interval(value: Any) -> Optional[int]:
    """'30m', '6h', '1d', '1w' -> secondes. None/'manual' -> None (manuel uniquement)."""
    if value in (None, "", "manual", "manuel"):
        return None
    m = re.fullmatch(r"(\d+)\s*([mhdw])", str(value).strip().lower())
    if not m:
        raise ConfigError(f"Intervalle invalide : {value!r} (exemples : 30m, 6h, 1d, 1w)")
    secs = int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
    if secs < 300:
        raise ConfigError("Intervalle minimal : 5m")
    return secs


def find_bin(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def ensure_dirs() -> None:
    for d, mode in ((CONFIG_DIR, 0o700), (PROFILES_DIR, 0o700), (SECRETS_DIR, 0o700), (STATE_DIR, 0o700)):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, mode)
        except OSError:
            pass


# =============================================================================
# Profils
# =============================================================================
def profile_path(name: str) -> Path:
    if not PROFILE_RE.match(name):
        raise ConfigError(f"Nom de profil invalide : {name!r} (lettres, chiffres, _ . - uniquement)")
    return PROFILES_DIR / f"{name}.json"


def list_profile_names() -> List[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json"))


def normalize_profile(cfg: Dict[str, Any], name: str) -> None:
    cfg["name"] = name
    cfg.setdefault("enabled", True)
    cfg.setdefault("databases", [])
    cfg.setdefault("paths", [])
    cfg.setdefault("exclude", [])
    cfg.setdefault("retention", {})
    cfg["retention"].setdefault("keep_min", 1)
    cfg.setdefault("encryption", {"enabled": False})
    cfg.setdefault("schedule", {"interval": "1d"})
    cfg.setdefault("work_dir", DEFAULT_WORK_DIR)
    for db in cfg["databases"]:
        db.setdefault("host", "localhost")
        db.setdefault("port", 3306)
    used = set()
    for p in cfg["paths"]:
        base = p.get("label") or re.sub(r"[^\w.\-]", "_", Path(p.get("path", "")).name or "root")
        label, i = base, 2
        while label in used:
            label, i = f"{base}{i}", i + 1
        used.add(label)
        p["label"] = label


def validate_profile(cfg: Dict[str, Any]) -> None:
    errs: List[str] = []
    if not cfg["databases"] and not cfg["paths"]:
        errs.append("Le profil doit contenir au moins une base de données ou un répertoire.")
    seen = set()
    for db in cfg["databases"]:
        n = db.get("name", "")
        if not DB_NAME_RE.match(n):
            errs.append(f"Nom de base invalide : {n!r}")
        if n in seen:
            errs.append(f"Base en double : {n}")
        seen.add(n)
        if not db.get("user"):
            errs.append(f"Base {n} : 'user' manquant")
    for p in cfg["paths"]:
        if not p.get("path") or not os.path.isabs(p["path"]):
            errs.append(f"Chemin absolu requis : {p.get('path')!r}")
        if not LABEL_RE.match(p["label"]):
            errs.append(f"Label invalide : {p['label']!r}")
    days = cfg["retention"].get("days")
    if not isinstance(days, int) or days < 1:
        errs.append("retention.days (entier >= 1) est obligatoire : le RGPD impose une durée de conservation limitée.")
    if not isinstance(cfg["retention"].get("keep_min"), int) or cfg["retention"]["keep_min"] < 1:
        errs.append("retention.keep_min doit être un entier >= 1")
    try:
        parse_interval(cfg["schedule"].get("interval"))
    except ConfigError as e:
        errs.append(str(e))
    if cfg["encryption"].get("enabled") and not cfg["encryption"].get("password"):
        errs.append("encryption.password requis quand le chiffrement est activé")
    st = cfg.get("storage", {})
    required = {"local": ["path"], "nfs": ["mount_point"], "s3": ["bucket"],
                "smb": ["server", "share", "username", "password"]}
    if st.get("type") not in required:
        errs.append("storage.type doit valoir : local, nfs, s3 ou smb")
    else:
        for k in required[st["type"]]:
            if not st.get(k):
                errs.append(f"storage.{k} manquant")
    smtp = cfg.get("smtp")
    if smtp:
        for k in ("host", "from", "to"):
            if not smtp.get(k):
                errs.append(f"smtp.{k} manquant")
        if smtp.get("security", "starttls") not in ("starttls", "ssl", "none"):
            errs.append("smtp.security doit valoir : starttls, ssl ou none")
    if errs:
        raise ConfigError("Profil invalide :\n  - " + "\n  - ".join(errs))


def load_profile(name: str) -> Dict[str, Any]:
    path = profile_path(name)
    if not path.exists():
        raise ConfigError(f"Profil introuvable : {name} (voir : list-profiles)")
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        raise ConfigError(f"JSON invalide dans {path} : {e}")
    if path.stat().st_mode & 0o077:
        log.warning("Permissions trop larges sur %s (faites : chmod 600)", path)
    normalize_profile(cfg, name)
    validate_profile(cfg)
    return cfg


def save_profile(cfg: Dict[str, Any]) -> Path:
    path = profile_path(cfg["name"])
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return path


# =============================================================================
# État (planification) et verrous
# =============================================================================
@contextmanager
def state_lock():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(STATE_DIR / "state.lock", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def load_state() -> Dict[str, Any]:
    try:
        with open(STATE_DIR / "state.json", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def update_state(name: str, **fields: Any) -> None:
    try:
        with state_lock():
            st = load_state()
            st.setdefault(name, {}).update(fields)
            tmp = STATE_DIR / "state.json.tmp"
            tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
            os.replace(tmp, STATE_DIR / "state.json")
    except OSError as e:
        log.warning("Impossible d'écrire l'état : %s", e)


def acquire_lock(name: str):
    d = STATE_DIR / "locks"
    d.mkdir(parents=True, exist_ok=True)
    f = open(d / f"{name}.lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        raise ProfileBusy(name)
    return f


def is_due(cfg: Dict[str, Any], st: Optional[Dict[str, Any]], now_ts: float) -> bool:
    interval = parse_interval(cfg["schedule"].get("interval"))
    if interval is None:
        return False
    tol = min(300, interval // 10)
    if not st or not st.get("last_attempt"):
        return True
    if st.get("last_status") == "failure":      # nouvel essai au plus tôt après 1 h
        return now_ts - st["last_attempt"] >= min(interval, 3600) - tol
    return now_ts - (st.get("last_success") or 0) >= interval - tol


# =============================================================================
# Chiffrement (AES-256-GCM par blocs de 1 Mo, clé scrypt)
#   Format : MAGIC(5) | salt(16) | nonce_prefix(8) | { len(4) | chunk_chiffré }*
#   Chaque bloc : nonce = prefix + compteur(4) ; AAD = en-tête + drapeau « dernier bloc »
#   => toute altération, réorganisation ou troncature est détectée.
# =============================================================================
MAGIC = b"WPBK\x01"
HEADER_LEN = len(MAGIC) + 16 + 8
CHUNK = 1 << 20


def _crypto():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        return AESGCM, Scrypt, InvalidTag
    except ImportError:
        raise BackupError("Module 'cryptography' manquant : pip install cryptography")


def _derive_key(password: str, salt: bytes) -> bytes:
    _, Scrypt, _ = _crypto()
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode("utf-8"))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    AESGCM, _, _ = _crypto()
    salt, prefix = os.urandom(16), os.urandom(8)
    header = MAGIC + salt + prefix
    aes = AESGCM(_derive_key(password, salt))
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(header)
        counter = 0
        chunk = fi.read(CHUNK)
        while True:
            nxt = fi.read(CHUNK)
            last = not nxt
            ct = aes.encrypt(prefix + counter.to_bytes(4, "big"), chunk,
                             header + (b"\x01" if last else b"\x00"))
            fo.write(len(ct).to_bytes(4, "big"))
            fo.write(ct)
            if last:
                break
            chunk, counter = nxt, counter + 1


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    AESGCM, _, InvalidTag = _crypto()
    with open(src, "rb") as fi:
        header = fi.read(HEADER_LEN)
        if len(header) != HEADER_LEN or not header.startswith(MAGIC):
            raise BackupError("Fichier non reconnu comme sauvegarde chiffrée wpbackup")
        salt = header[len(MAGIC):len(MAGIC) + 16]
        prefix = header[-8:]
        aes = AESGCM(_derive_key(password, salt))
        with open(dst, "wb") as fo:
            raw = fi.read(4)
            counter = 0
            while True:
                if len(raw) != 4:
                    raise BackupError("Fichier chiffré tronqué")
                n = int.from_bytes(raw, "big")
                if n > CHUNK + 16:
                    raise BackupError("Fichier chiffré corrompu")
                ct = fi.read(n)
                nxt = fi.read(4)
                if len(ct) != n or (nxt and len(nxt) != 4):
                    raise BackupError("Fichier chiffré tronqué")
                last = not nxt
                try:
                    pt = aes.decrypt(prefix + counter.to_bytes(4, "big"), ct,
                                     header + (b"\x01" if last else b"\x00"))
                except InvalidTag:
                    raise BackupError("Déchiffrement impossible : mot de passe incorrect ou fichier altéré")
                fo.write(pt)
                if last:
                    break
                raw, counter = nxt, counter + 1


# =============================================================================
# Stockages distants
# =============================================================================
class Backend:
    kind = "?"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def describe(self) -> str: raise NotImplementedError
    def put(self, src: Path, name: str) -> None: raise NotImplementedError
    def get(self, name: str, dst: Path) -> None: raise NotImplementedError
    def list(self) -> List[str]: raise NotImplementedError
    def delete(self, name: str) -> None: raise NotImplementedError
    def size(self, name: str) -> int: raise NotImplementedError


class LocalBackend(Backend):
    kind = "local"

    def __init__(self, base: Path, profile: str):
        self.dir = Path(base) / profile

    def describe(self) -> str:
        return f"{self.kind}:{self.dir}"

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def put(self, src: Path, name: str) -> None:
        self._ensure()
        tmp = self.dir / (name + ".part")
        shutil.copyfile(src, tmp)
        os.replace(tmp, self.dir / name)

    def get(self, name: str, dst: Path) -> None:
        shutil.copyfile(self.dir / name, dst)

    def list(self) -> List[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.name for p in self.dir.iterdir() if p.is_file() and not p.name.endswith(".part"))

    def delete(self, name: str) -> None:
        (self.dir / name).unlink(missing_ok=True)

    def size(self, name: str) -> int:
        return (self.dir / name).stat().st_size


class NFSBackend(LocalBackend):
    """NFS : utilise un point de montage existant, ou le monte si server/export sont fournis."""
    kind = "nfs"

    def __init__(self, cfg: Dict[str, Any], profile: str):
        self.cfg = cfg
        self.mp = Path(cfg["mount_point"])
        super().__init__(self.mp / cfg.get("subdir", ""), profile)
        self.mounted_by_us = False

    def __enter__(self):
        if not os.path.ismount(self.mp):
            if not (self.cfg.get("server") and self.cfg.get("export")):
                raise BackupError(f"{self.mp} n'est pas un point de montage actif "
                                  "(montez-le, ou renseignez storage.server et storage.export)")
            self.mp.mkdir(parents=True, exist_ok=True)
            opts = self.cfg.get("options", "vers=4,soft,timeo=100")
            r = subprocess.run(["mount", "-t", "nfs", "-o", opts,
                                f"{self.cfg['server']}:{self.cfg['export']}", str(self.mp)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise BackupError(f"Montage NFS impossible : {r.stderr.strip()} "
                                  "(en conteneur LXC non privilégié, montez le partage sur l'hôte)")
            self.mounted_by_us = True
        return self

    def __exit__(self, *exc):
        if self.mounted_by_us:
            subprocess.run(["umount", str(self.mp)], capture_output=True)
        return False


class S3Backend(Backend):
    kind = "s3"

    def __init__(self, cfg: Dict[str, Any], profile: str):
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise BackupError("Module 'boto3' manquant : pip install boto3")
        self.bucket = cfg["bucket"]
        prefix = cfg.get("prefix", "wpbackup").strip("/")
        self.prefix = "/".join(x for x in (prefix, profile) if x) + "/"
        kw: Dict[str, Any] = {}
        if cfg.get("region"):
            kw["region_name"] = cfg["region"]
        if cfg.get("endpoint_url"):
            kw["endpoint_url"] = cfg["endpoint_url"]
        if cfg.get("access_key"):
            kw["aws_access_key_id"] = resolve_secret(cfg["access_key"])
            kw["aws_secret_access_key"] = resolve_secret(cfg.get("secret_key"))
        self.s3 = boto3.client("s3", config=Config(retries={"max_attempts": 5, "mode": "standard"}), **kw)
        self.extra: Dict[str, Any] = {}
        if cfg.get("sse"):
            self.extra["ServerSideEncryption"] = "AES256"
        if cfg.get("storage_class"):
            self.extra["StorageClass"] = cfg["storage_class"]
        region = cfg.get("region", "")
        if not cfg.get("endpoint_url") and region and not region.startswith("eu-"):
            log.warning("RGPD : la région S3 %s est hors UE - vérifiez la base légale du transfert "
                        "(clauses contractuelles types, etc.)", region)

    def describe(self) -> str:
        return f"s3://{self.bucket}/{self.prefix}"

    def put(self, src: Path, name: str) -> None:
        self.s3.upload_file(str(src), self.bucket, self.prefix + name, ExtraArgs=self.extra or None)

    def get(self, name: str, dst: Path) -> None:
        self.s3.download_file(self.bucket, self.prefix + name, str(dst))

    def list(self) -> List[str]:
        names = []
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                n = obj["Key"][len(self.prefix):]
                if n and "/" not in n:
                    names.append(n)
        return sorted(names)

    def delete(self, name: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=self.prefix + name)

    def size(self, name: str) -> int:
        return int(self.s3.head_object(Bucket=self.bucket, Key=self.prefix + name)["ContentLength"])


class SMBBackend(Backend):
    kind = "smb"

    def __init__(self, cfg: Dict[str, Any], profile: str):
        try:
            import smbclient
        except ImportError:
            raise BackupError("Module 'smbprotocol' manquant : pip install smbprotocol")
        self.smb = smbclient
        server, share = cfg["server"], cfg["share"]
        sub = cfg.get("path", "").strip("/\\").replace("/", "\\")
        self.base = f"\\\\{server}\\{share}" + (f"\\{sub}" if sub else "") + f"\\{profile}"
        user = cfg["username"]
        if cfg.get("domain"):
            user = f"{cfg['domain']}\\{user}"
        smbclient.register_session(server, username=user, password=resolve_secret(cfg["password"]),
                                   port=int(cfg.get("port", 445)),
                                   encrypt=True if cfg.get("encrypt") else None,
                                   connection_timeout=30)

    def _p(self, name: str) -> str:
        return f"{self.base}\\{name}"

    def describe(self) -> str:
        return "smb:" + self.base

    def put(self, src: Path, name: str) -> None:
        self.smb.makedirs(self.base, exist_ok=True)
        tmp = self._p(name + ".part")
        with open(src, "rb") as fi, self.smb.open_file(tmp, mode="wb") as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)
        try:
            self.smb.remove(self._p(name))
        except Exception:
            pass
        self.smb.rename(tmp, self._p(name))

    def get(self, name: str, dst: Path) -> None:
        with self.smb.open_file(self._p(name), mode="rb") as fi, open(dst, "wb") as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)

    def list(self) -> List[str]:
        try:
            return sorted(n for n in self.smb.listdir(self.base) if not n.endswith(".part"))
        except Exception as e:
            if "NO_SUCH" in str(e).upper() or "not found" in str(e).lower():
                return []
            raise

    def delete(self, name: str) -> None:
        self.smb.remove(self._p(name))

    def size(self, name: str) -> int:
        return int(self.smb.stat(self._p(name)).st_size)


def make_backend(cfg: Dict[str, Any]) -> Backend:
    st, name = cfg["storage"], cfg["name"]
    t = st["type"]
    if t == "local":
        return LocalBackend(Path(st["path"]), name)
    if t == "nfs":
        return NFSBackend(st, name)
    if t == "s3":
        return S3Backend(st, name)
    if t == "smb":
        return SMBBackend(st, name)
    raise ConfigError(f"Type de stockage inconnu : {t}")


# =============================================================================
# Base de données
# =============================================================================
@lru_cache(maxsize=None)
def _tool_help(binary: str) -> str:
    try:
        r = subprocess.run([binary, "--help"], capture_output=True, text=True, timeout=20)
        return r.stdout + r.stderr
    except Exception:
        return ""


def _cnf_quote(v: Any) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_client_cnf(db: Dict[str, Any], path: Path) -> None:
    """Fichier d'options 0600 : le mot de passe ne figure JAMAIS dans la ligne de commande."""
    lines = ["[client]", f"user={_cnf_quote(db['user'])}"]
    pw = resolve_secret(db.get("password"))
    if pw:
        lines.append(f"password={_cnf_quote(pw)}")
    if db.get("socket"):
        lines.append(f"socket={_cnf_quote(db['socket'])}")
    else:
        lines.append(f"host={_cnf_quote(db.get('host', 'localhost'))}")
        lines.append(f"port={int(db.get('port', 3306))}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def dump_database(db: Dict[str, Any], dest: Path, workdir: Path) -> None:
    binary = find_bin("mysqldump", "mariadb-dump")
    if not binary:
        raise BackupError("mysqldump / mariadb-dump introuvable (installez le client MariaDB/MySQL)")
    cnf = workdir / f"client-{os.getpid()}-{db['name']}.cnf"
    write_client_cnf(db, cnf)
    cmd = [binary, f"--defaults-extra-file={cnf}", "--single-transaction", "--quick",
           "--default-character-set=utf8mb4"]
    h = _tool_help(binary)
    if "no-tablespaces" in h:
        cmd.append("--no-tablespaces")          # évite l'erreur de privilège PROCESS (MySQL 8)
    if "column-statistics" in h:
        cmd.append("--column-statistics=0")     # client MySQL 8 vers serveur MariaDB/5.7
    extra = list(db.get("extra_args", []))
    cmd += extra + [db["name"]]
    try:
        with open(dest, "wb") as out:
            p = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE)
    finally:
        cnf.unlink(missing_ok=True)
    err = p.stderr.decode("utf-8", "replace").strip()
    if p.returncode != 0:
        raise BackupError(f"Dump de la base « {db['name']} » en échec : {scrub(err)}")
    if "--skip-comments" not in extra:
        size = dest.stat().st_size
        with open(dest, "rb") as f:
            f.seek(max(0, size - 1024))
            if b"Dump completed" not in f.read():
                raise BackupError(f"Dump de « {db['name']} » incomplet (marqueur de fin absent)")


def restore_database(db: Dict[str, Any], sql_path: Path, workdir: Path) -> None:
    binary = find_bin("mysql", "mariadb")
    if not binary:
        raise BackupError("Client mysql / mariadb introuvable")
    cnf = workdir / f"restore-{os.getpid()}-{db['name']}.cnf"
    write_client_cnf(db, cnf)
    try:
        # Création de la base si elle n'existe pas (au mieux : peut échouer faute de privilège)
        subprocess.run([binary, f"--defaults-extra-file={cnf}", "-e",
                        f"CREATE DATABASE IF NOT EXISTS `{db['name']}` CHARACTER SET utf8mb4"],
                       capture_output=True)
        with open(sql_path, "rb") as f:
            p = subprocess.run([binary, f"--defaults-extra-file={cnf}",
                                "--default-character-set=utf8mb4", db["name"]],
                               stdin=f, stderr=subprocess.PIPE)
    finally:
        cnf.unlink(missing_ok=True)
    if p.returncode != 0:
        raise BackupError(f"Import de la base « {db['name']} » en échec : "
                          f"{scrub(p.stderr.decode('utf-8', 'replace').strip())}")


# =============================================================================
# Archive des répertoires
# =============================================================================
def _excluded(rel: str, patterns: List[str]) -> bool:
    for pat in patterns:
        pat = pat.strip().strip("/")
        if not pat:
            continue
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat) or rel.startswith(pat + "/"):
            return True
    return False


def add_tree(tar: tarfile.TarFile, root: Path, arc_root: str, excludes: List[str], warnings: List[str]) -> int:
    count = 0

    def add(path: Path, arc: str) -> None:
        nonlocal count
        try:
            tar.add(str(path), arcname=arc, recursive=False)
            count += 1
        except (OSError, tarfile.TarError) as e:
            warnings.append(f"Élément ignoré : {path} ({scrub(e)})")

    if not root.is_dir():
        add(root, arc_root)
        return count
    root = root.resolve()
    add(root, arc_root)
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: warnings.append(f"Lecture impossible : {e}")):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        kept = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if _excluded(rel, excludes):
                continue
            kept.append(d)
            add(Path(dirpath) / d, f"{arc_root}/{rel}")
        dirnames[:] = kept
        for f in sorted(filenames):
            rel = f"{rel_dir}/{f}" if rel_dir else f
            if not _excluded(rel, excludes):
                add(Path(dirpath) / f, f"{arc_root}/{rel}")
    return count


def build_archive(cfg: Dict[str, Any], dumps: List[Tuple[str, Path]], archive: Path,
                  manifest: Dict[str, Any], warnings: List[str]) -> int:
    n = 0
    with tarfile.open(archive, "w:gz", compresslevel=6) as tar:
        data = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
        ti = tarfile.TarInfo("manifest.json")
        ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
        tar.addfile(ti, io.BytesIO(data))
        for name, path in dumps:
            tar.add(str(path), arcname=f"db/{name}.sql", recursive=False)
        for p in cfg["paths"]:
            n += add_tree(tar, Path(p["path"]), f"files/{p['label']}", cfg["exclude"], warnings)
    return n


# =============================================================================
# Résultat, rapport, e-mail
# =============================================================================
@dataclass
class RunResult:
    profile: str
    start: dt.datetime
    end: Optional[dt.datetime] = None
    status: str = "failure"
    archive: str = ""
    size: int = 0
    sha256: str = ""
    encrypted: bool = False
    destination: str = ""
    databases: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    files_count: int = 0
    expired: List[Tuple[str, dt.datetime]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: str = ""


def _cap(lines: List[str], limit: int = 20) -> List[str]:
    if len(lines) <= limit:
        return lines
    return lines[:limit] + [f"… et {len(lines) - limit} autre(s) (voir le journal)"]


def build_report(cfg: Dict[str, Any], res: RunResult) -> Tuple[str, str]:
    ok = res.status == "success"
    host = socket.gethostname()
    word = "SUCCÈS" if ok else "ÉCHEC"
    subject = f"[wpbackup] {word} - {res.profile} - {host} - {res.start.strftime(DATE_FMT)}"
    end = res.end or dt.datetime.now()
    L = [f"Sauvegarde du profil « {res.profile} » : {word}", "",
         f"Serveur        : {host}",
         f"Début          : {res.start.strftime(DATE_FMT)}",
         f"Fin            : {end.strftime(DATE_FMT)}",
         f"Durée          : {human_duration((end - res.start).total_seconds())}"]
    if res.archive:
        L += [f"Archive        : {res.archive} ({human_size(res.size)})",
              f"Chiffrement    : {'oui (AES-256-GCM)' if res.encrypted else 'NON - sauvegarde en clair'}",
              f"SHA-256        : {res.sha256}",
              f"Destination    : {res.destination}"]
    if res.databases:
        L.append(f"Bases          : {', '.join(res.databases)}")
    if res.paths:
        L.append(f"Répertoires    : {', '.join(res.paths)} ({res.files_count} éléments)")
    ret = cfg["retention"]
    L.append(f"Rétention      : {ret['days']} jour(s), minimum {ret['keep_min']} sauvegarde(s) conservée(s)")
    L.append("")
    if ok:
        if res.expired:
            L.append(f"Sauvegardes expirées supprimées ({len(res.expired)}) :")
            L += [f"  - {n} (sauvegarde du {ts.strftime(DATE_FMT)})" for n, ts in res.expired]
        else:
            L.append("Aucune sauvegarde expirée à supprimer.")
    else:
        L.append("Rétention non appliquée (sauvegarde en échec) : aucune ancienne sauvegarde supprimée.")
    if res.warnings:
        L += ["", "Avertissements :"] + [f"  - {w}" for w in _cap(res.warnings)]
    if res.error:
        L += ["", "Erreur :", f"  {res.error}"]
    L += ["", f"-- wpbackup {VERSION}"]
    return subject, "\n".join(L)


def send_mail(smtp_cfg: Dict[str, Any], subject: str, body: str) -> None:
    to = smtp_cfg["to"] if isinstance(smtp_cfg["to"], list) else [smtp_cfg["to"]]
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, smtp_cfg["from"], ", ".join(to)
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg.set_content(body)
    sec = smtp_cfg.get("security", "starttls")
    host = smtp_cfg["host"]
    port = int(smtp_cfg.get("port", 465 if sec == "ssl" else 587))
    ctx = ssl.create_default_context()
    srv = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx) if sec == "ssl" else smtplib.SMTP(host, port, timeout=30)
    with srv:
        srv.ehlo()
        if sec == "starttls":
            srv.starttls(context=ctx)
            srv.ehlo()
        if smtp_cfg.get("user"):
            srv.login(smtp_cfg["user"], resolve_secret(smtp_cfg.get("password")) or "")
        srv.send_message(msg)


def notify(cfg: Dict[str, Any], subject: str, body: str, success: bool) -> None:
    smtp = cfg.get("smtp")
    if not smtp or not smtp.get("to"):
        return
    mode = smtp.get("notify_on", "always")
    if mode == "never" or (mode == "failure" and success):
        return
    try:
        send_mail(smtp, subject, body)
        log.info("Notification envoyée à %s", smtp["to"])
    except Exception as e:
        log.error("Envoi du mail impossible : %s", scrub(e))


# =============================================================================
# Sauvegarde
# =============================================================================
@dataclass
class Entry:
    name: str
    ts: dt.datetime
    encrypted: bool


def parse_entries(profile: str, names: List[str]) -> List[Entry]:
    out = []
    for n in names:
        m = BACKUP_RE.match(n)
        if m and m.group("profile") == profile:
            try:
                out.append(Entry(n, dt.datetime.strptime(m.group("ts"), TS_FORMAT), bool(m.group("enc"))))
            except ValueError:
                continue
    return sorted(out, key=lambda e: e.ts, reverse=True)


def apply_retention(cfg: Dict[str, Any], be: Backend, current: str, now: dt.datetime,
                    res: RunResult) -> None:
    """Appelée UNIQUEMENT après une sauvegarde réussie et vérifiée."""
    days, keep_min = cfg["retention"]["days"], cfg["retention"]["keep_min"]
    entries = parse_entries(cfg["name"], be.list())
    cutoff = now - dt.timedelta(days=days)
    protected = {e.name for e in entries[:keep_min]} | {current}
    for e in reversed(entries):                      # du plus ancien au plus récent
        if e.ts >= cutoff or e.name in protected:
            continue
        try:
            be.delete(e.name)
            try:
                be.delete(e.name + ".meta.json")
            except Exception:
                pass
            res.expired.append((e.name, e.ts))
            log.info("Rétention : %s supprimée (du %s)", e.name, e.ts.strftime(DATE_FMT))
            audit("retention_delete", profile=cfg["name"], archive=e.name, backup_date=e.ts.isoformat())
        except Exception as ex:
            res.warnings.append(f"Suppression de {e.name} impossible : {scrub(ex)}")


def make_workdir(cfg: Dict[str, Any]) -> Path:
    base = Path(cfg["work_dir"])
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    return Path(tempfile.mkdtemp(prefix=f"{cfg['name']}-", dir=base))


def run_backup(cfg: Dict[str, Any]) -> Optional[RunResult]:
    name = cfg["name"]
    try:
        lock = acquire_lock(name)
    except ProfileBusy:
        log.warning("Profil « %s » déjà en cours d'exécution - ignoré", name)
        return None
    res = RunResult(profile=name, start=dt.datetime.now())
    update_state(name, last_attempt=res.start.timestamp())
    workdir: Optional[Path] = None
    try:
        log.info("=== Sauvegarde du profil %s ===", name)
        enc = cfg["encryption"]
        password = None
        if enc.get("enabled"):
            password = resolve_secret(enc.get("password"))
            if not password:
                raise BackupError("Mot de passe de chiffrement vide")
        else:
            log.warning("Chiffrement DÉSACTIVÉ pour %s : déconseillé au titre de l'art. 32 du RGPD", name)
        workdir = make_workdir(cfg)
        base = f"{name}_{res.start.strftime(TS_FORMAT)}"

        # Fail-fast : on vérifie la destination avant le travail lourd
        with make_backend(cfg) as be:
            res.destination = be.describe()
            be.list()

            # 1. Dumps SQL
            dumps: List[Tuple[str, Path]] = []
            for db in cfg["databases"]:
                log.info("Dump de la base %s…", db["name"])
                dest = workdir / f"{db['name']}.sql"
                dump_database(db, dest, workdir)
                dumps.append((db["name"], dest))
                res.databases.append(db["name"])

            # 2. Manifeste + archive
            manifest = {
                "version": 1, "tool": f"wpbackup {VERSION}", "profile": name,
                "created_at": res.start.isoformat(timespec="seconds"),
                "databases": [{"name": n, "file": f"db/{n}.sql"} for n, _ in dumps],
                "paths": [],
            }
            for p in cfg["paths"]:
                src = Path(p["path"])
                if not src.exists():
                    raise BackupError(f"Répertoire introuvable : {src}")
                manifest["paths"].append({"label": p["label"], "path": p["path"],
                                          "type": "dir" if src.is_dir() else "file"})
                res.paths.append(p["label"])
            log.info("Création de l'archive…")
            archive = workdir / f"{base}.tar.gz"
            res.files_count = build_archive(cfg, dumps, archive, manifest, res.warnings)
            for _, d in dumps:
                d.unlink(missing_ok=True)       # on supprime vite les dumps en clair

            # 3. Chiffrement (optionnel)
            final = archive
            if password:
                log.info("Chiffrement AES-256-GCM…")
                final = workdir / f"{base}.tar.gz.enc"
                encrypt_file(archive, final, password)
                archive.unlink()
            res.archive, res.encrypted = final.name, bool(password)
            res.size, res.sha256 = final.stat().st_size, sha256_file(final)

            meta = {"version": 1, "profile": name, "created_at": res.start.isoformat(timespec="seconds"),
                    "archive": final.name, "size": res.size, "sha256": res.sha256,
                    "encrypted": res.encrypted, "databases": res.databases, "paths": res.paths}
            meta_path = workdir / (final.name + ".meta.json")
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

            # 4. Envoi + vérification
            log.info("Envoi vers %s (%s)…", res.destination, human_size(res.size))
            be.put(final, final.name)
            remote = be.size(final.name)
            if remote != res.size:
                try:
                    be.delete(final.name)
                except Exception:
                    pass
                raise BackupError(f"Vérification de taille échouée après envoi ({remote} ≠ {res.size})")
            try:
                be.put(meta_path, meta_path.name)
            except Exception as e:
                res.warnings.append(f"Métadonnées non envoyées : {scrub(e)}")

            # 5. Succès confirmé -> rétention
            res.status = "success"
            try:
                apply_retention(cfg, be, final.name, res.start, res)
            except Exception as e:
                res.warnings.append(f"Rétention non appliquée : {scrub(e)}")
    except Exception as e:
        res.status = "failure"
        res.error = scrub(f"{type(e).__name__}: {e}")
        log.error("ÉCHEC de la sauvegarde %s : %s", name, res.error)
        log.debug(scrub(traceback.format_exc()))
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        lock.close()
    res.end = dt.datetime.now()
    st: Dict[str, Any] = {"last_status": res.status}
    if res.status == "success":
        st["last_success"] = res.start.timestamp()
        st["last_archive"] = res.archive
    update_state(name, **st)
    audit("backup_" + res.status, profile=name, archive=res.archive, size=res.size,
          encrypted=res.encrypted, destination=res.destination,
          expired_deleted=[n for n, _ in res.expired], error=res.error or None)
    subject, body = build_report(cfg, res)
    notify(cfg, subject, body, res.status == "success")
    return res


# =============================================================================
# Restauration (rollback)
# =============================================================================
def parse_user_date(s: str) -> dt.datetime:
    fmts = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
            "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d", "%d/%m/%Y"]
    for f in fmts:
        try:
            d = dt.datetime.strptime(s.strip(), f)
            return d if "%H" in f else d.replace(hour=23, minute=59, second=59)
        except ValueError:
            continue
    raise ConfigError(f"Date invalide : {s!r} (ex : 2026-10-20, '2026-10-20 14:30' ou 20/10/2026)")


def get_backup_password(cfg: Dict[str, Any]) -> str:
    try:
        pw = resolve_secret(cfg["encryption"].get("password"))
        if pw:
            return pw
    except ConfigError as e:
        log.warning("%s", e)
    if not sys.stdin.isatty():
        raise BackupError("Mot de passe de chiffrement introuvable et terminal non interactif")
    pw = getpass.getpass("Mot de passe de déchiffrement de la sauvegarde : ")
    register_secret(pw)
    return pw


def confirm(question: str, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return False
    raw = input(f"{question} [{'O/n' if default else 'o/N'}] ").strip().lower()
    return default if not raw else raw in ("o", "oui", "y", "yes")


def select_entry(entries: List[Entry], be: Backend, args: argparse.Namespace) -> Entry:
    if args.backup:
        for e in entries:
            if e.name == args.backup:
                return e
        raise ConfigError(f"Sauvegarde introuvable : {args.backup}")
    if args.date:
        target = parse_user_date(args.date)
        for e in entries:                           # entries est trié du plus récent au plus ancien
            if e.ts <= target:
                return e
        raise ConfigError(f"Aucune sauvegarde à la date {target.strftime(DATE_FMT)} ou avant "
                          f"(la plus ancienne : {entries[-1].ts.strftime(DATE_FMT)})")
    if not sys.stdin.isatty():
        raise ConfigError("Précisez --date ou --backup (terminal non interactif)")
    print("\nSauvegardes disponibles :")
    for i, e in enumerate(entries, 1):
        try:
            sz = human_size(be.size(e.name))
        except Exception:
            sz = "?"
        print(f"  {i:>3}. {e.ts.strftime(DATE_FMT)}  {sz:>10}  {'chiffrée' if e.encrypted else 'en clair'}")
    while True:
        raw = input("Numéro de la sauvegarde à restaurer [1 = la plus récente] : ").strip() or "1"
        if raw.isdigit() and 1 <= int(raw) <= len(entries):
            return entries[int(raw) - 1]


def _extract(tar: tarfile.TarFile, member: tarfile.TarInfo, path: Path) -> None:
    kw: Dict[str, Any] = {"numeric_owner": True}
    if hasattr(tarfile, "fully_trusted_filter"):     # Python >= 3.12 / rétroportages
        kw["filter"] = "fully_trusted"               # nos propres contrôles sont faits avant
    tar.extract(member, path=str(path), **kw)


def _safe_rel(rel: str) -> str:
    if rel.startswith("/") or ".." in rel.split("/"):
        raise BackupError(f"Entrée d'archive dangereuse refusée : {rel!r}")
    return rel


def cmd_restore(args: argparse.Namespace) -> int:
    cfg = load_profile(args.profile)
    started = dt.datetime.now()
    with make_backend(cfg) as be:
        entries = parse_entries(cfg["name"], be.list())
        if not entries:
            raise ConfigError("Aucune sauvegarde trouvée pour ce profil.")
        entry = select_entry(entries, be, args)
        print(f"\nSauvegarde sélectionnée : {entry.name}  ({entry.ts.strftime(DATE_FMT)})")
        workdir = make_workdir(cfg)
        status, detail = "failure", ""
        try:
            local = workdir / entry.name
            log.info("Téléchargement…")
            be.get(entry.name, local)
            try:                                       # vérification d'intégrité par checksum
                mp = workdir / "meta.json"
                be.get(entry.name + ".meta.json", mp)
                expected = json.loads(mp.read_text(encoding="utf-8")).get("sha256")
                if expected and sha256_file(local) != expected:
                    raise BackupError("SHA-256 différent : archive corrompue ou altérée")
            except BackupError:
                raise
            except Exception:
                log.warning("Métadonnées absentes : checksum non vérifié")
            plain = local
            if entry.encrypted:
                plain = workdir / "restore.tar.gz"
                log.info("Déchiffrement…")
                decrypt_file(local, plain, get_backup_password(cfg))
                local.unlink()
            detail = _do_restore(cfg, args, plain, workdir, entry)
            status = "success"
        except UserCancelled:
            print("Restauration annulée.")
            return 1
        except Exception as e:
            detail = scrub(f"{type(e).__name__}: {e}")
            log.error("ÉCHEC de la restauration : %s", detail)
            audit("restore_failure", profile=cfg["name"], archive=entry.name, error=detail)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    subject = f"[wpbackup] RESTAURATION {'RÉUSSIE' if status == 'success' else 'EN ÉCHEC'} - {cfg['name']} - {socket.gethostname()}"
    body = (f"Restauration du profil « {cfg['name']} »\nSauvegarde : {entry.name} ({entry.ts.strftime(DATE_FMT)})\n"
            f"Début : {started.strftime(DATE_FMT)}\nFin   : {dt.datetime.now().strftime(DATE_FMT)}\n\n{detail}\n")
    notify(cfg, subject, body, status == "success")
    return 0 if status == "success" else 1


def _do_restore(cfg: Dict[str, Any], args: argparse.Namespace, archive: Path,
                workdir: Path, entry: Entry) -> str:
    stamp = dt.datetime.now().strftime(TS_FORMAT)
    target = Path(args.target) if args.target else None
    report: List[str] = []
    with tarfile.open(archive, "r:gz") as tar:
        try:
            manifest = json.load(tar.extractfile("manifest.json"))
        except Exception:
            raise BackupError("manifest.json absent ou illisible dans l'archive")
        dbs = [] if args.only == "files" else [d for d in manifest["databases"] if not args.db or d["name"] in args.db]
        paths = [] if args.only == "db" else [p for p in manifest["paths"] if not args.path or p["label"] in args.path]
        if not dbs and not paths:
            raise ConfigError("Rien à restaurer avec ces filtres.")

        print("\nÉléments à restaurer :")
        for d in dbs:
            print(f"  - base de données  {d['name']}")
        for p in paths:
            print(f"  - {p['type']:<4} {p['label']}  ->  {(target / p['label']) if target else p['path']}")
        if target:
            print(f"\nMode inspection : tout est extrait dans {target} (rien n'est écrasé).")
        else:
            print("\nATTENTION : les bases et répertoires ci-dessus vont être REMPLACÉS.\n"
                  "Les anciennes données sont conservées (dump de sécurité / répertoire .pre-restore-*).")
        if not args.yes and not confirm("Confirmer la restauration ?"):
            raise UserCancelled()
        audit("restore_start", profile=cfg["name"], archive=entry.name,
              databases=[d["name"] for d in dbs], paths=[p["label"] for p in paths],
              target=str(target) if target else None)

        # --- Bases de données
        for d in dbs:
            member = f"db/{_safe_rel(d['name'])}.sql"
            sql = workdir / f"{d['name']}.sql"
            src = tar.extractfile(member)
            if src is None:
                raise BackupError(f"{member} absent de l'archive")
            with open(sql, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            if target:
                (target / "db").mkdir(parents=True, exist_ok=True)
                shutil.copyfile(sql, target / "db" / f"{d['name']}.sql")
                os.chmod(target / "db" / f"{d['name']}.sql", 0o600)
                report.append(f"Dump extrait : {target}/db/{d['name']}.sql")
            else:
                db_cfg = next((x for x in cfg["databases"] if x["name"] == d["name"]), None)
                if not db_cfg:
                    raise BackupError(f"La base « {d['name']} » n'est plus déclarée dans le profil "
                                      "(ajoutez-la ou utilisez --target)")
                if not args.no_safety:
                    safe_dir = STATE_DIR / "pre-restore"
                    safe_dir.mkdir(parents=True, exist_ok=True)
                    os.chmod(safe_dir, 0o700)
                    safe = safe_dir / f"{d['name']}_avant-restauration_{stamp}.sql"
                    log.info("Dump de sécurité de %s -> %s", d["name"], safe)
                    dump_database(db_cfg, safe, workdir)
                    report.append(f"Dump de sécurité : {safe}  (à supprimer une fois la restauration validée - RGPD)")
                log.info("Import de la base %s…", d["name"])
                restore_database(db_cfg, sql, workdir)
                report.append(f"Base restaurée : {d['name']}")
            sql.unlink(missing_ok=True)

        # --- Fichiers (une seule passe sur l'archive)
        if paths:
            plan: Dict[str, Dict[str, Any]] = {}
            for p in paths:
                orig = Path(p["path"])
                if target:
                    staging = target / p["label"] if p["type"] == "dir" else target / "files" / p["label"]
                else:
                    staging = (orig.parent / f".{orig.name}.restore-{stamp}") if p["type"] == "dir" \
                        else workdir / f"file-{p['label']}"
                staging.mkdir(parents=True, exist_ok=True)
                plan[p["label"]] = {"p": p, "orig": orig, "staging": staging, "root": None}
            for m in tar:
                if not m.name.startswith("files/"):
                    continue
                label, _, rel = m.name[len("files/"):].partition("/")
                item = plan.get(label)
                if item is None:
                    continue
                if item["p"]["type"] == "file":
                    rel = item["orig"].name
                if rel == "":
                    item["root"] = m
                    continue
                _safe_rel(rel)
                if m.isdev() or m.isfifo():
                    continue
                m2 = copy.copy(m)
                m2.name = rel
                if m2.islnk():
                    m2.linkname = _safe_rel(m2.linkname.partition("/")[2].partition("/")[2])
                _extract(tar, m2, item["staging"])
            for label, item in plan.items():
                staging, orig, p = item["staging"], item["orig"], item["p"]
                if target:
                    report.append(f"Extrait : {staging}")
                    continue
                if p["type"] == "dir":
                    if item["root"] is not None:
                        os.chmod(staging, item["root"].mode)
                        try:
                            os.chown(staging, item["root"].uid, item["root"].gid)
                        except (OSError, AttributeError):
                            pass
                    new = staging
                else:
                    new = staging / orig.name
                if orig.exists() or orig.is_symlink():
                    old = orig.with_name(f"{orig.name}.pre-restore-{stamp}")
                    os.rename(orig, old)
                    report.append(f"Ancienne version conservée : {old}  (à supprimer après validation - RGPD)")
                orig.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(new), str(orig))
                report.append(f"Restauré : {orig}")
    audit("restore_success", profile=cfg["name"], archive=entry.name)
    msg = "\n".join(report)
    print("\n" + msg + "\n\nRestauration terminée.")
    if not target:
        print("Pensez à vider les caches WordPress et à vérifier le site.")
        print("RGPD : si des demandes d'effacement ont été traitées depuis cette sauvegarde, "
              "réappliquez-les maintenant.")
    return msg


# =============================================================================
# Assistant interactif
# =============================================================================
def ask(prompt: str, default: Optional[str] = None, secret: bool = False,
        required: bool = True, validator=None) -> str:
    while True:
        suffix = f" [{default}]" if default not in (None, "") and not secret else ""
        if secret:
            raw = getpass.getpass(f"{prompt} : ").rstrip("\r\n")
        else:
            raw = input(f"{prompt}{suffix} : ").strip()
        if not raw and default is not None:
            raw = default
        if not raw and required:
            print("  Valeur requise.")
            continue
        if raw and validator:
            err = validator(raw)
            if err:
                print(f"  {err}")
                continue
        return raw


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    while True:
        raw = input(f"{prompt} [{'O/n' if default else 'o/N'}] : ").strip().lower()
        if not raw:
            return default
        if raw in ("o", "oui", "y", "yes"):
            return True
        if raw in ("n", "non", "no"):
            return False


def ask_choice(prompt: str, choices: List[str], default: str) -> str:
    return ask(f"{prompt} ({'/'.join(choices)})", default=default,
               validator=lambda v: None if v in choices else f"Choix possibles : {', '.join(choices)}")


def find_wp_config(p: Path) -> Optional[Path]:
    for c in (p, p / "wp-config.php", p.parent / "wp-config.php"):
        if c.is_file() and c.name == "wp-config.php":
            return c
    return None


_WP_DEFINE = r'''define\s*\(\s*([\'"])%s\1\s*,\s*([\'"])((?:\\.|(?!\2).)*)\2\s*\)'''


def parse_wp_config(path: Path) -> Dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: Dict[str, str] = {}
    for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"):
        m = re.search(_WP_DEFINE % key, text, re.S)
        if m:
            val = m.group(3)
            val = re.sub(r"\\([\\'])", r"\1", val) if m.group(2) == "'" else re.sub(r'\\(["\\$])', r"\1", val)
            out[key] = val
    return out


def split_db_host(h: str) -> Dict[str, Any]:
    if not h:
        return {"host": "localhost"}
    if ":" in h and not h.startswith("["):
        host, _, rest = h.partition(":")
        if rest.startswith("/"):
            return {"host": host or "localhost", "socket": rest}
        if rest.isdigit():
            return {"host": host or "localhost", "port": int(rest)}
        return {"host": host or "localhost"}
    return {"host": h}


def wizard_storage() -> Dict[str, Any]:
    t = ask_choice("Type de stockage", ["local", "nfs", "s3", "smb"], "local")
    if t == "local":
        print("  Attention : un dossier local ne protège pas d'une perte du serveur (règle 3-2-1).")
        return {"type": "local", "path": ask("Dossier de destination", "/var/backups/wpbackup")}
    if t == "nfs":
        print("  En LXC non privilégié, montez le partage sur l'hôte puis exposez-le au conteneur.")
        st = {"type": "nfs", "mount_point": ask("Point de montage", "/mnt/backup-nfs")}
        srv = ask("Serveur NFS (vide si déjà monté)", "", required=False)
        if srv:
            st["server"] = srv
            st["export"] = ask("Export NFS (ex: /export/backups)")
        return st
    if t == "s3":
        st: Dict[str, Any] = {"type": "s3", "bucket": ask("Nom du bucket"),
                              "prefix": ask("Préfixe", "wpbackup")}
        endpoint = ask("Endpoint S3 compatible (vide pour AWS)", "", required=False)
        if endpoint:
            st["endpoint_url"] = endpoint
        st["region"] = ask("Région", "eu-west-3" if not endpoint else "", required=False)
        if st["region"] and not endpoint and not st["region"].startswith("eu-"):
            print("  RGPD : région hors UE - vérifiez la base légale du transfert.")
        if ask_yes_no("Saisir des clés d'accès ? (sinon : rôle IAM / variables AWS_*)", True):
            st["access_key"] = ask("Access key ID")
            st["secret_key"] = ask("Secret access key", secret=True)
        return st
    st = {"type": "smb", "server": ask("Serveur SMB (nom ou IP)"), "share": ask("Nom du partage"),
          "path": ask("Sous-dossier dans le partage", "", required=False),
          "username": ask("Utilisateur"), "password": ask("Mot de passe", secret=True)}
    dom = ask("Domaine (facultatif)", "", required=False)
    if dom:
        st["domain"] = dom
    st["encrypt"] = ask_yes_no("Imposer le chiffrement SMB 3 du transport ?", False)
    return st


def wizard_smtp(existing: List[Tuple[str, Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    if not ask_yes_no("Configurer les notifications par e-mail (SMTP) ?", True):
        return None
    if existing and ask_yes_no(f"Réutiliser les réglages SMTP du profil « {existing[0][0]} » ?", True):
        smtp = copy.deepcopy(existing[0][1])
    else:
        sec = ask_choice("Sécurité", ["starttls", "ssl", "none"], "starttls")
        smtp = {"host": ask("Serveur SMTP"), "security": sec,
                "port": int(ask("Port", "465" if sec == "ssl" else "587", validator=lambda v: None if v.isdigit() else "Nombre attendu"))}
        user = ask("Utilisateur SMTP (vide si aucun)", "", required=False)
        if user:
            smtp["user"] = user
            smtp["password"] = ask("Mot de passe SMTP", secret=True)
        smtp["from"] = ask("Adresse expéditeur", f"wpbackup@{socket.getfqdn()}")
        if sec == "none":
            print("  Attention : SMTP sans chiffrement.")
    to = ask("Destinataire(s), séparés par des virgules")
    smtp["to"] = [x.strip() for x in to.split(",") if x.strip()]
    smtp["notify_on"] = ask_choice("Envoyer un mail", ["always", "failure"], "always")
    return smtp


def cmd_create_profile(args: argparse.Namespace) -> int:
    print(f"\n=== Création d'un scénario de sauvegarde (wpbackup {VERSION}) ===\n")
    name = args.name or ask("Nom du profil (ex: monsite-prod)",
                            validator=lambda v: None if PROFILE_RE.match(v) else "Lettres, chiffres, _ . - uniquement")
    if args.name and not PROFILE_RE.match(name):
        raise ConfigError("Nom de profil invalide")
    if profile_path(name).exists() and not ask_yes_no(f"Le profil « {name} » existe déjà. L'écraser ?", False):
        return 1
    cfg: Dict[str, Any] = {"description": ask("Description (facultatif)", "", required=False),
                           "enabled": True, "databases": [], "paths": []}

    print("\n-- 1/6  Répertoires et bases de données --")
    print("  Indiquez le dossier du site WordPress : les identifiants de base seront lus dans wp-config.php.")
    while True:
        p = ask("Répertoire à sauvegarder (vide pour terminer)", "", required=False)
        if not p:
            break
        pp = Path(p)
        if not pp.exists() and not ask_yes_no("  Ce chemin n'existe pas. L'ajouter quand même ?", False):
            continue
        cfg["paths"].append({"path": str(pp)})
        wpc = find_wp_config(pp) if pp.exists() else None
        if wpc:
            info = parse_wp_config(wpc)
            if info.get("DB_NAME") and info.get("DB_USER"):
                print(f"  wp-config.php détecté : base « {info['DB_NAME']} » (utilisateur {info['DB_USER']})")
                if ask_yes_no("  Sauvegarder cette base ?", True) and \
                        info["DB_NAME"] not in [d["name"] for d in cfg["databases"]]:
                    db = {"name": info["DB_NAME"], "user": info["DB_USER"],
                          "password": info.get("DB_PASSWORD", "")}
                    db.update(split_db_host(info.get("DB_HOST", "localhost")))
                    cfg["databases"].append(db)
    while ask_yes_no("Ajouter une base de données manuellement ?", not cfg["databases"] and not cfg["paths"]):
        db = {"name": ask("Nom de la base", validator=lambda v: None if DB_NAME_RE.match(v) else "Nom invalide"),
              "host": ask("Hôte", "localhost"),
              "port": int(ask("Port", "3306", validator=lambda v: None if v.isdigit() else "Nombre attendu")),
              "user": ask("Utilisateur"), "password": ask("Mot de passe", secret=True, required=False)}
        cfg["databases"].append(db)
    if cfg["paths"]:
        ex = ask("Exclusions (motifs séparés par des virgules)",
                 "wp-content/cache,wp-content/upgrade,wp-content/updraft,wp-content/ai1wm-backups,*.log")
        cfg["exclude"] = [x.strip() for x in ex.split(",") if x.strip()]

    print("\n-- 2/6  Chiffrement --")
    if ask_yes_no("Chiffrer les sauvegardes (AES-256-GCM) ? Fortement recommandé (RGPD art. 32)", True):
        while True:
            pw = ask("Mot de passe de chiffrement (12 caractères minimum)", secret=True)
            if len(pw) < 12:
                print("  Trop court.")
                continue
            if pw != ask("Confirmez le mot de passe", secret=True):
                print("  Les mots de passe diffèrent.")
                continue
            break
        ensure_dirs()
        keyfile = SECRETS_DIR / f"{name}.key"
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw + "\n")
        cfg["encryption"] = {"enabled": True, "password": f"file:{keyfile}"}
        print(f"  Mot de passe enregistré dans {keyfile} (chmod 600).")
        print("  IMPORTANT : conservez-le aussi dans un gestionnaire de mots de passe.\n"
              "  Sans lui, AUCUNE restauration n'est possible.")
    else:
        cfg["encryption"] = {"enabled": False}
        print("  Les sauvegardes seront en clair. Assurez-vous que la destination est chiffrée et protégée.")

    print("\n-- 3/6  Rétention (RGPD : conservation limitée) --")
    days = int(ask("Durée de conservation en jours", "30",
                   validator=lambda v: None if v.isdigit() and int(v) >= 1 else "Entier >= 1"))
    cfg["retention"] = {"days": days, "keep_min": 1}

    print("\n-- 4/6  Fréquence --")
    print("  Exemples : 6h, 1d, 7d  - ou « manuel » (lancement à la main uniquement).")

    def _chk_interval(v: str) -> Optional[str]:
        try:
            parse_interval(v)
            return None
        except ConfigError as e:
            return str(e)
    cfg["schedule"] = {"interval": ask("Fréquence de sauvegarde", "1d", validator=_chk_interval)}

    print("\n-- 5/6  Stockage --")
    cfg["storage"] = wizard_storage()

    print("\n-- 6/6  Notifications --")
    existing = []
    for other in list_profile_names():
        try:
            o = json.loads(profile_path(other).read_text(encoding="utf-8"))
            if o.get("smtp") and other != name:
                existing.append((other, o["smtp"]))
        except (OSError, ValueError):
            pass
    smtp = wizard_smtp(existing)
    if smtp:
        cfg["smtp"] = smtp

    normalize_profile(cfg, name)
    validate_profile(cfg)
    ensure_dirs()
    path = save_profile(cfg)
    audit("profile_created", profile=name)
    print(f"\nProfil enregistré : {path}")

    if cfg.get("smtp") and ask_yes_no("Envoyer un e-mail de test maintenant ?", True):
        try:
            send_mail(cfg["smtp"], f"[wpbackup] Test - {name}", "Ceci est un message de test wpbackup.")
            print("  E-mail de test envoyé.")
        except Exception as e:
            print(f"  Échec : {scrub(e)}")
    if ask_yes_no("Tester l'accès au stockage maintenant ?", True):
        try:
            with make_backend(cfg) as be:
                be.list()
            print("  Stockage accessible.")
        except Exception as e:
            print(f"  Échec : {scrub(e)}")
    print(f"\nProchaines étapes :\n  python3 {Path(__file__).name} run {name}          # première sauvegarde\n"
          f"  python3 {Path(__file__).name} install-scheduler   # planification automatique\n")
    return 0


# =============================================================================
# Autres commandes
# =============================================================================
def mask_secrets(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: ("***" if k in ("password", "secret_key", "access_key") and isinstance(v, str)
                    and not v.startswith(("env:", "file:")) else mask_secrets(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [mask_secrets(x) for x in o]
    return o


def print_result(res: RunResult) -> None:
    if res.status == "success":
        print(f"[OK]    {res.profile} : {res.archive} ({human_size(res.size)}) -> {res.destination}"
              + (f" - {len(res.expired)} sauvegarde(s) expirée(s) supprimée(s)" if res.expired else ""))
    else:
        print(f"[ÉCHEC] {res.profile} : {res.error}")
    for w in res.warnings:
        print(f"        ! {w}")


def cmd_run(args: argparse.Namespace) -> int:
    names = [n for n in list_profile_names() if load_enabled(n)] if args.all else args.profiles
    if not names:
        raise ConfigError("Indiquez un ou plusieurs profils, ou --all.")
    failures = 0
    for n in names:
        try:
            cfg = load_profile(n)
        except ConfigError as e:
            log.error("%s", e)
            print(f"[ÉCHEC] {n} : {e}")
            failures += 1
            continue
        res = run_backup(cfg)
        if res is None:
            print(f"[IGNORÉ] {n} : déjà en cours")
            continue
        print_result(res)
        failures += res.status != "success"
    return 1 if failures else 0


def load_enabled(name: str) -> bool:
    try:
        return bool(json.loads(profile_path(name).read_text(encoding="utf-8")).get("enabled", True))
    except (OSError, ValueError):
        return True


def cmd_run_due(args: argparse.Namespace) -> int:
    state, now_ts, failures = load_state(), time.time(), 0
    for n in list_profile_names():
        if not load_enabled(n):
            continue
        try:
            cfg = load_profile(n)
            if not is_due(cfg, state.get(n), now_ts):
                continue
        except ConfigError as e:
            log.error("%s", e)
            failures += 1
            continue
        res = run_backup(cfg)
        failures += bool(res and res.status != "success")
    return 1 if failures else 0


def cmd_list_profiles(args: argparse.Namespace) -> int:
    names = list_profile_names()
    if not names:
        print("Aucun profil. Créez-en un avec : create-profile")
        return 0
    state = load_state()
    print(f"{'PROFIL':<24}{'ACTIF':<7}{'FRÉQUENCE':<11}{'RÉTENTION':<11}{'STOCKAGE':<9}{'CHIFFRÉ':<9}DERNIER SUCCÈS")
    for n in names:
        try:
            c = load_profile(n)
        except ConfigError:
            print(f"{n:<24}(profil invalide)")
            continue
        last = state.get(n, {}).get("last_success")
        last_s = dt.datetime.fromtimestamp(last).strftime(DATE_FMT) if last else "-"
        print(f"{n:<24}{'oui' if c['enabled'] else 'non':<7}{str(c['schedule'].get('interval') or 'manuel'):<11}"
              f"{str(c['retention']['days']) + ' j':<11}{c['storage']['type']:<9}"
              f"{'oui' if c['encryption'].get('enabled') else 'non':<9}{last_s}")
    return 0


def cmd_show_profile(args: argparse.Namespace) -> int:
    cfg = load_profile(args.profile)
    print(json.dumps(mask_secrets(cfg), indent=2, ensure_ascii=False))
    return 0


def cmd_list_backups(args: argparse.Namespace) -> int:
    cfg = load_profile(args.profile)
    with make_backend(cfg) as be:
        entries = parse_entries(cfg["name"], be.list())
        if not entries:
            print("Aucune sauvegarde.")
            return 0
        print(f"Sauvegardes de « {cfg['name']} » sur {be.describe()} :")
        for e in entries:
            try:
                sz = human_size(be.size(e.name))
            except Exception:
                sz = "?"
            exp = e.ts + dt.timedelta(days=cfg["retention"]["days"])
            print(f"  {e.ts.strftime(DATE_FMT)}  {sz:>10}  {'chiffrée' if e.encrypted else 'en clair':<9} "
                  f"expire le {exp.strftime('%d/%m/%Y')}   {e.name}")
    return 0


def cmd_test_mail(args: argparse.Namespace) -> int:
    cfg = load_profile(args.profile)
    if not cfg.get("smtp"):
        raise ConfigError("Aucun SMTP configuré dans ce profil.")
    send_mail(cfg["smtp"], f"[wpbackup] Test - {cfg['name']}", "Ceci est un message de test wpbackup.")
    print("E-mail de test envoyé.")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    def chk(label: str, ok: bool, hint: str = "") -> None:
        print(f"  [{'OK' if ok else '!!'}] {label}" + (f"   -> {hint}" if not ok and hint else ""))
    print(f"wpbackup {VERSION} - Python {sys.version.split()[0]}\n")
    chk("Python >= 3.8", sys.version_info >= (3, 8), "installez python3.9+ (RHEL 8 : dnf install python3.11)")
    chk("Exécution en root (restauration fidèle des droits)", os.geteuid() == 0, "lancez avec sudo / root")
    chk("mysqldump ou mariadb-dump", bool(find_bin("mysqldump", "mariadb-dump")),
        "Debian/Ubuntu : apt install mariadb-client | RHEL : dnf install mariadb")
    chk("mysql ou mariadb (restauration)", bool(find_bin("mysql", "mariadb")), "même paquet que ci-dessus")
    for mod, pkg, use in (("cryptography", "cryptography", "chiffrement"), ("boto3", "boto3", "stockage S3"),
                          ("smbclient", "smbprotocol", "stockage SMB")):
        try:
            __import__(mod)
            ok = True
        except ImportError:
            ok = False
        chk(f"Module {mod} ({use})", ok, f"pip install {pkg}")
    chk("mount.nfs (seulement si montage NFS par le script)", bool(find_bin("mount.nfs")),
        "Debian/Ubuntu : apt install nfs-common | RHEL : dnf install nfs-utils")
    chk("Planificateur : systemd ou cron", Path("/run/systemd/system").exists() or bool(find_bin("crond", "cron")),
        "apt install cron | dnf install cronie")
    print(f"\n  Config : {CONFIG_DIR}\n  État   : {STATE_DIR}\n  Logs   : {LOG_DIR}")
    return 0


def cmd_install_scheduler(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise ConfigError("Droits root requis.")
    script = os.path.abspath(__file__)
    exe = f"{sys.executable} {script} run-due"
    env_lines = [f"{k}={os.environ[k]}" for k in ("WPBACKUP_CONFIG_DIR", "WPBACKUP_STATE_DIR",
                                                   "WPBACKUP_LOG_DIR", "WPBACKUP_WORK_DIR") if k in os.environ]
    kind = args.type
    if kind == "auto":
        kind = "systemd" if Path("/run/systemd/system").exists() and find_bin("systemctl") else "cron"
    tick = int(args.tick)
    if kind == "cron":
        content = ("# Géré par wpbackup - exécute les profils dont l'échéance est atteinte\n"
                   "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\nMAILTO=\"\"\n"
                   + "".join(l + "\n" for l in env_lines)
                   + f"*/{tick} * * * * root {exe} >/dev/null 2>&1\n")
        p = Path("/etc/cron.d/wpbackup")
        p.write_text(content, encoding="utf-8")
        os.chmod(p, 0o644)
        print(f"Cron installé : {p} (vérification toutes les {tick} min).")
    else:
        svc = ("[Unit]\nDescription=wpbackup - sauvegardes WordPress planifiées\n\n[Service]\nType=oneshot\n"
               + "".join(f"Environment={l}\n" for l in env_lines) + f"ExecStart={exe}\n")
        timer = (f"[Unit]\nDescription=wpbackup - déclencheur\n\n[Timer]\nOnBootSec=5min\n"
                 f"OnUnitActiveSec={tick}min\nAccuracySec=30s\n\n[Install]\nWantedBy=timers.target\n")
        Path("/etc/systemd/system/wpbackup.service").write_text(svc, encoding="utf-8")
        Path("/etc/systemd/system/wpbackup.timer").write_text(timer, encoding="utf-8")
        os.chmod("/etc/systemd/system/wpbackup.service", 0o644)
        os.chmod("/etc/systemd/system/wpbackup.timer", 0o644)
        subprocess.run(["systemctl", "daemon-reload"])
        subprocess.run(["systemctl", "enable", "--now", "wpbackup.timer"])
        print(f"Timer systemd installé et activé (vérification toutes les {tick} min).")
    print("Chaque profil se déclenche selon sa propre fréquence (champ schedule.interval).")
    return 0


# =============================================================================
# Point d'entrée
# =============================================================================
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="wpbackup", description="Sauvegarde WordPress chiffrée, orientée RGPD")
    ap.add_argument("-v", "--verbose", action="store_true", help="logs détaillés")
    ap.add_argument("--version", action="version", version=f"wpbackup {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("create-profile", help="assistant de création d'un profil")
    s.add_argument("name", nargs="?")
    s.set_defaults(func=cmd_create_profile)

    sub.add_parser("list-profiles", help="liste les profils").set_defaults(func=cmd_list_profiles)

    s = sub.add_parser("show-profile", help="affiche un profil (secrets masqués)")
    s.add_argument("profile")
    s.set_defaults(func=cmd_show_profile)

    s = sub.add_parser("run", help="exécute une ou plusieurs sauvegardes")
    s.add_argument("profiles", nargs="*")
    s.add_argument("--all", action="store_true", help="tous les profils actifs")
    s.set_defaults(func=cmd_run)

    sub.add_parser("run-due", help="lance les profils dont l'échéance est atteinte").set_defaults(func=cmd_run_due)

    s = sub.add_parser("list-backups", help="liste les sauvegardes d'un profil")
    s.add_argument("profile")
    s.set_defaults(func=cmd_list_backups)

    s = sub.add_parser("restore", help="restaure une sauvegarde (rollback)")
    s.add_argument("profile")
    s.add_argument("--date", help="restaure la dernière sauvegarde <= cette date (2026-10-20, '2026-10-20 14:30', 20/10/2026)")
    s.add_argument("--backup", help="nom exact de l'archive")
    s.add_argument("--only", choices=["all", "db", "files"], default="all")
    s.add_argument("--db", action="append", help="ne restaurer que cette base (répétable)")
    s.add_argument("--path", action="append", help="ne restaurer que ce label de répertoire (répétable)")
    s.add_argument("--target", help="extraire dans ce dossier au lieu d'écraser (inspection)")
    s.add_argument("--no-safety", action="store_true", help="pas de dump de sécurité avant import SQL")
    s.add_argument("--yes", "-y", action="store_true", help="ne pas demander de confirmation")
    s.set_defaults(func=cmd_restore)

    s = sub.add_parser("test-mail", help="envoie un e-mail de test")
    s.add_argument("profile")
    s.set_defaults(func=cmd_test_mail)

    sub.add_parser("doctor", help="vérifie les dépendances").set_defaults(func=cmd_doctor)

    s = sub.add_parser("install-scheduler", help="installe cron.d ou un timer systemd")
    s.add_argument("--type", choices=["auto", "cron", "systemd"], default="auto")
    s.add_argument("--tick", default="10", help="période de vérification en minutes (défaut : 10)")
    s.set_defaults(func=cmd_install_scheduler)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        if args.cmd in ("create-profile", "install-scheduler"):
            ensure_dirs()
        return args.func(args)
    except ConfigError as e:
        print(f"Erreur de configuration : {scrub(e)}", file=sys.stderr)
        return 2
    except BackupError as e:
        print(f"Erreur : {scrub(e)}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"Droits insuffisants : {e}\nLancez le script en root ou définissez WPBACKUP_CONFIG_DIR / "
              "WPBACKUP_STATE_DIR / WPBACKUP_LOG_DIR.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrompu.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
