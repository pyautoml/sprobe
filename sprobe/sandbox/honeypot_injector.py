"""
Honeypot secret injector.

Creates fake credential files and environment variables inside the
sandbox. If the package under analysis touches any of these, it is
immediately flagged as malicious — legitimate packages never read
another application's credentials.

Honeypot files contain unique canary strings (PROBE_CANARY_xxx) that
can be detected in strace output to confirm access.

Each honeypot run gets a unique session ID so canary strings are
unpredictable and cannot be hardcoded around by malware.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass(frozen=True, slots=True)
class HoneypotEnvironment:
    """
    Complete honeypot setup for a sandbox session.

    :param home_dir: Path to the fake home directory containing honeypot files.
    :param env_vars: Environment variables to inject (fake API keys, tokens).
    :param canary_paths: File paths that should never be accessed.
    :param canary_token: Unique session token embedded in all honeypot content.
    """

    home_dir: Path
    env_vars: Dict[str, str]
    canary_paths: List[str]
    canary_token: str


def create_honeypot_environment(sandbox_temp_dir: Path) -> HoneypotEnvironment:
    """
    Create a full honeypot environment inside a temporary directory.

    Sets up fake credential files and generates environment variables
    with canary tokens. The caller passes these to the bwrap sandbox.

    :param sandbox_temp_dir: Temporary directory to create honeypot files in.
    :returns: Complete honeypot configuration for the sandbox.
    """
    canary_token = f"PROBE_CANARY_{uuid.uuid4().hex[:12]}"

    home_dir = sandbox_temp_dir / "fakehome"
    home_dir.mkdir(exist_ok=True)

    canary_paths: List[str] = []

    canary_paths.extend(_create_ssh_honeypot(home_dir, canary_token))
    canary_paths.extend(_create_aws_honeypot(home_dir, canary_token))
    canary_paths.extend(_create_env_honeypot(home_dir, canary_token))
    canary_paths.extend(_create_git_honeypot(home_dir, canary_token))

    env_vars = _build_canary_env_vars(canary_token)

    return HoneypotEnvironment(
        home_dir=home_dir,
        env_vars=env_vars,
        canary_paths=canary_paths,
        canary_token=canary_token,
    )


def _create_ssh_honeypot(home_dir: Path, canary_token: str) -> List[str]:
    """
    Create fake SSH key files.

    :param home_dir: Fake home directory.
    :param canary_token: Unique canary string.
    :returns: List of created honeypot file paths (as they appear inside sandbox).
    """
    ssh_dir = home_dir / ".ssh"
    ssh_dir.mkdir(exist_ok=True)

    fake_key_content = (
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{canary_token}_SSH_PRIVATE_KEY\n"
        f"-----END OPENSSH PRIVATE KEY-----\n"
    )

    for key_name in ("id_rsa", "id_ed25519"):
        key_path = ssh_dir / key_name
        key_path.write_text(fake_key_content, encoding="utf-8")

    return ["/home/user/.ssh/id_rsa", "/home/user/.ssh/id_ed25519"]


def _create_aws_honeypot(home_dir: Path, canary_token: str) -> List[str]:
    """
    Create fake AWS credential files.

    :param home_dir: Fake home directory.
    :param canary_token: Unique canary string.
    :returns: List of created honeypot file paths.
    """
    aws_dir = home_dir / ".aws"
    aws_dir.mkdir(exist_ok=True)

    credentials_content = (
        f"[default]\n"
        f"aws_access_key_id = {canary_token}_AWS_KEY_ID\n"
        f"aws_secret_access_key = {canary_token}_AWS_SECRET\n"
    )

    credentials_path = aws_dir / "credentials"
    credentials_path.write_text(credentials_content, encoding="utf-8")

    return ["/home/user/.aws/credentials"]


def _create_env_honeypot(home_dir: Path, canary_token: str) -> List[str]:
    """
    Create fake .env file with canary tokens.

    :param home_dir: Fake home directory.
    :param canary_token: Unique canary string.
    :returns: List of created honeypot file paths.
    """
    env_content = (
        f"DATABASE_URL=postgresql://{canary_token}_DB_USER:{canary_token}_DB_PASS@localhost/app\n"
        f"SECRET_KEY={canary_token}_DJANGO_SECRET\n"
        f"API_KEY={canary_token}_API_KEY\n"
    )

    env_path = home_dir / ".env"
    env_path.write_text(env_content, encoding="utf-8")

    return ["/home/user/.env"]


def _create_git_honeypot(home_dir: Path, canary_token: str) -> List[str]:
    """
    Create fake Git credential files.

    :param home_dir: Fake home directory.
    :param canary_token: Unique canary string.
    :returns: List of created honeypot file paths.
    """
    git_credentials_content = (
        f"https://{canary_token}_GIT_USER:{canary_token}_GIT_TOKEN@github.com\n"
    )

    git_creds_path = home_dir / ".git-credentials"
    git_creds_path.write_text(git_credentials_content, encoding="utf-8")

    return ["/home/user/.git-credentials"]


def _build_canary_env_vars(canary_token: str) -> Dict[str, str]:
    """
    Build fake environment variables with canary tokens.

    These are injected into the sandbox environment. If the package
    reads any of these via os.getenv(), strace will not directly
    catch it (env vars are in-process), but the honeypot files cover
    the file-based credential theft vector.

    :param canary_token: Unique canary string.
    :returns: Dict of env var name to canary value.
    """
    return {
        "OPENAI_API_KEY": f"{canary_token}_OPENAI",
        "AWS_SECRET_ACCESS_KEY": f"{canary_token}_AWS_SECRET",
        "AWS_ACCESS_KEY_ID": f"{canary_token}_AWS_KEY",
        "GITHUB_TOKEN": f"{canary_token}_GITHUB",
        "ANTHROPIC_API_KEY": f"{canary_token}_ANTHROPIC",
        "DATABASE_URL": f"postgresql://{canary_token}_USER:{canary_token}_PASS@localhost/db",
        "SECRET_KEY": f"{canary_token}_SECRET",
    }


__all__ = [
    "HoneypotEnvironment",
    "create_honeypot_environment",
]
