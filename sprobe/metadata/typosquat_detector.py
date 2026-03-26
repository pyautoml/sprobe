"""
Typosquatting detector.

Compares a package name against a list of popular PyPI packages
using Levenshtein edit distance. If a package name is suspiciously
close to a popular package but not identical, it is likely a
typosquatting attack (e.g. 'requets' targeting 'requests').

Uses a custom Levenshtein implementation — zero external dependencies.

The algorithm is O(n*m) where n and m are the string lengths.
For package names (typically under 30 chars), this is negligible.
"""

from __future__ import annotations

from typing import Optional, Tuple

# Edit distance threshold — packages within this distance are flagged
# 1 = single typo (most common attack vector)
# 2 = catches transpositions and double typos
_MAX_EDIT_DISTANCE: int = 2

# Minimum package name length to check — very short names
# produce too many false positives
_MIN_NAME_LENGTH: int = 4

# Top PyPI packages by download count (2024-2025)
# This list covers the most targeted packages for typosquatting
_POPULAR_PACKAGES: frozenset[str] = frozenset(
    {
        "requests",
        "boto3",
        "urllib3",
        "setuptools",
        "typing-extensions",
        "botocore",
        "certifi",
        "charset-normalizer",
        "idna",
        "numpy",
        "pip",
        "python-dateutil",
        "packaging",
        "pyyaml",
        "s3transfer",
        "six",
        "wheel",
        "cryptography",
        "cffi",
        "pycparser",
        "jinja2",
        "markupsafe",
        "pyasn1",
        "rsa",
        "colorama",
        "attrs",
        "click",
        "pygments",
        "platformdirs",
        "filelock",
        "importlib-metadata",
        "tomli",
        "zipp",
        "pyparsing",
        "pytz",
        "pluggy",
        "soupsieve",
        "beautifulsoup4",
        "virtualenv",
        "protobuf",
        "grpcio",
        "pillow",
        "scipy",
        "pandas",
        "google-api-core",
        "google-auth",
        "googleapis-common-protos",
        "pyarrow",
        "wrapt",
        "decorator",
        "jsonschema",
        "pydantic",
        "aiohttp",
        "multidict",
        "yarl",
        "frozenlist",
        "aiosignal",
        "async-timeout",
        "flask",
        "werkzeug",
        "itsdangerous",
        "django",
        "sqlalchemy",
        "psycopg2",
        "celery",
        "redis",
        "fastapi",
        "uvicorn",
        "starlette",
        "httpx",
        "httpcore",
        "anyio",
        "sniffio",
        "h11",
        "pyjwt",
        "paramiko",
        "docker",
        "kubernetes",
        "awscli",
        "azure-core",
        "tensorflow",
        "torch",
        "transformers",
        "openai",
        "langchain",
        "anthropic",
        "tiktoken",
        "tokenizers",
        "scikit-learn",
        "matplotlib",
        "seaborn",
        "plotly",
        "pytest",
        "coverage",
        "tox",
        "black",
        "isort",
        "ruff",
        "mypy",
        "pylint",
        "flake8",
        "bandit",
        "rich",
        "typer",
        "loguru",
        "python-dotenv",
        "gunicorn",
        "nginx",
        "scrapy",
        "selenium",
        "playwright",
    }
)


def detect_typosquatting(
    package_name: str,
) -> Optional[Tuple[str, int]]:
    """
    Check if a package name is suspiciously similar to a popular package.

    :param package_name: Name of the package to check.
    :returns: Tuple of (similar_package_name, edit_distance), or None if no match.
    """
    normalized_name = package_name.lower().replace("_", "-")

    if len(normalized_name) < _MIN_NAME_LENGTH:
        return None

    # Exact match = not typosquatting
    if normalized_name in _POPULAR_PACKAGES:
        return None

    closest_match: Optional[str] = None
    closest_distance: int = _MAX_EDIT_DISTANCE + 1

    for popular_name in _POPULAR_PACKAGES:
        # Quick length filter — edit distance cannot be less than length difference
        length_difference = abs(len(normalized_name) - len(popular_name))
        if length_difference > _MAX_EDIT_DISTANCE:
            continue

        distance = _levenshtein_distance(normalized_name, popular_name)

        if distance <= _MAX_EDIT_DISTANCE and distance < closest_distance:
            closest_distance = distance
            closest_match = popular_name

    if closest_match is not None:
        return (closest_match, closest_distance)

    return None


def _levenshtein_distance(source: str, target: str) -> int:
    """
    Compute the Levenshtein edit distance between two strings.

    Standard dynamic programming approach, O(n*m) time and O(min(n,m)) space.
    Uses a single-row optimization to minimize memory usage.

    :param source: First string.
    :param target: Second string.
    :returns: Minimum number of single-character edits to transform source into target.
    """
    if source == target:
        return 0

    source_length = len(source)
    target_length = len(target)

    if source_length == 0:
        return target_length
    if target_length == 0:
        return source_length

    # Ensure source is the shorter string for space optimization
    if source_length > target_length:
        source, target = target, source
        source_length, target_length = target_length, source_length

    # Single-row DP — only need previous row to compute current
    previous_row = list(range(source_length + 1))

    for target_index in range(1, target_length + 1):
        current_row = [target_index] + [0] * source_length

        for source_index in range(1, source_length + 1):
            if source[source_index - 1] == target[target_index - 1]:
                substitution_cost = 0
            else:
                substitution_cost = 1

            current_row[source_index] = min(
                current_row[source_index - 1] + 1,  # insertion
                previous_row[source_index] + 1,  # deletion
                previous_row[source_index - 1] + substitution_cost,  # substitution
            )

        previous_row = current_row

    return previous_row[source_length]


__all__ = [
    "detect_typosquatting",
]
