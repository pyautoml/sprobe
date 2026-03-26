"""Tests for honeypot injector."""

import tempfile
from pathlib import Path

from sprobe.sandbox.honeypot_injector import create_honeypot_environment


def test_honeypot_creates_ssh_keys() -> None:
    """Honeypot must create fake SSH key files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        honeypot = create_honeypot_environment(Path(temp_dir))
        ssh_key = honeypot.home_dir / ".ssh" / "id_rsa"
        assert ssh_key.exists()
        content = ssh_key.read_text()
        assert honeypot.canary_token in content


def test_honeypot_creates_aws_credentials() -> None:
    """Honeypot must create fake AWS credential file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        honeypot = create_honeypot_environment(Path(temp_dir))
        aws_creds = honeypot.home_dir / ".aws" / "credentials"
        assert aws_creds.exists()
        content = aws_creds.read_text()
        assert honeypot.canary_token in content


def test_honeypot_creates_env_file() -> None:
    """Honeypot must create fake .env file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        honeypot = create_honeypot_environment(Path(temp_dir))
        env_file = honeypot.home_dir / ".env"
        assert env_file.exists()


def test_honeypot_creates_git_credentials() -> None:
    """Honeypot must create fake git credentials."""
    with tempfile.TemporaryDirectory() as temp_dir:
        honeypot = create_honeypot_environment(Path(temp_dir))
        git_creds = honeypot.home_dir / ".git-credentials"
        assert git_creds.exists()


def test_honeypot_env_vars_contain_canary() -> None:
    """All honeypot env vars must contain the unique canary token."""
    with tempfile.TemporaryDirectory() as temp_dir:
        honeypot = create_honeypot_environment(Path(temp_dir))
        for env_value in honeypot.env_vars.values():
            assert honeypot.canary_token in env_value


def test_honeypot_canary_token_unique() -> None:
    """Each honeypot session must produce a unique canary token."""
    with tempfile.TemporaryDirectory() as temp_dir_a:
        honeypot_a = create_honeypot_environment(Path(temp_dir_a))
    with tempfile.TemporaryDirectory() as temp_dir_b:
        honeypot_b = create_honeypot_environment(Path(temp_dir_b))
    assert honeypot_a.canary_token != honeypot_b.canary_token


def test_honeypot_canary_paths_populated() -> None:
    """Canary paths list must contain all expected honeypot locations."""
    with tempfile.TemporaryDirectory() as temp_dir:
        honeypot = create_honeypot_environment(Path(temp_dir))
        assert len(honeypot.canary_paths) >= 4
        path_str = " ".join(honeypot.canary_paths)
        assert ".ssh" in path_str
        assert ".aws" in path_str
        assert ".env" in path_str
        assert ".git-credentials" in path_str
