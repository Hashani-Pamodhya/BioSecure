
import hashlib


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def check_file_integrity(file_path, trusted_hash):
    """Check whether a file matches its trusted hash."""
    current_hash = calculate_sha256(file_path)
    return current_hash == trusted_hash
