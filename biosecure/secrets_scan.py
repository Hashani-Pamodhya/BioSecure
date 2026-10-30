
import re
from pathlib import Path

from biosecure.finding import SecurityFinding


# File types that BioSecure can scan as text.
TEXT_EXTENSIONS = {
    ".py", ".r", ".ipynb", ".sh", ".bash",
    ".env", ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg", ".conf", ".txt", ".sql",
    ".xml", ".properties"
}

# Avoid scanning files that are too large.
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


# Look for credentials assigned to suspicious variable names.
SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b(password|passwd|api_key|apikey|secret_key|access_token|
    auth_token|client_secret|db_password|database_password)\b\s*[:=]\s*["']([^"' ]{6,})["']""",
    re.VERBOSE
)

# Look for some recognisable token formats.
TOKEN_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
]


PLACEHOLDERS = {
    "your_api_key",
    "your_password",
    "your_secret",
    "change_me",
    "changeme",
    "example",
    "placeholder",
    "password",
    "secret",
    "none",
    "null",
}


def scan_file(file_path, project_root):
    """Scan one text file for possible hardcoded credentials."""

    findings = []

    try:
        if file_path.is_symlink() or file_path.stat().st_size > MAX_FILE_SIZE:
            return findings

        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):

        # Skip ordinary comments for this initial scanner.
        stripped_line = line.strip()
        if stripped_line.startswith(("#", "//")):
            continue

        matches = []

        assignment_match = SECRET_ASSIGNMENT.search(line)

        if assignment_match:
            secret_value = assignment_match.group(2)

            if secret_value.lower() not in PLACEHOLDERS:
                matches.append("credential-like assignment")

        for pattern in TOKEN_PATTERNS:
            if pattern.search(line):
                matches.append("recognisable token format")

        if matches:
            relative_path = file_path.relative_to(project_root)

            findings.append(
                SecurityFinding(
                    module="secrets_scan",
                    severity="HIGH",
                    title="Possible hardcoded credential detected",
                    file=str(relative_path),
                    description=(
                        "A possible credential was detected in this file. "
                        "The actual value is not included in the finding."
                    ),
                    recommendation=(
                        "Remove the credential from the source code, "
                        "rotate it if it is real, and store it securely "
                        "using environment variables or a secrets manager."
                    ),
                    line=line_number,
                    confidence="MEDIUM",
                )
            )

    return findings


def scan_secrets(project_path):
    """Scan a project directory for possible hardcoded credentials."""

    project_root = Path(project_path).resolve()
    findings = []

    if not project_root.is_dir():
        raise ValueError("The supplied project path is not a directory.")

    for file_path in project_root.rglob("*"):

        if not file_path.is_file() or file_path.is_symlink():
            continue

        if file_path.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        findings.extend(scan_file(file_path, project_root))

    return findings
