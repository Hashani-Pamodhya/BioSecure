
from biosecure.secrets_scan import scan_secrets


def test_detect_api_key(tmp_path):
    """Check whether an API key is detected."""

    project = tmp_path / "sample_project"
    project.mkdir()

    file = project / "pipeline.py"
    file.write_text('api_key = "ABC123XYZ987SECRET"\n')

    findings = scan_secrets(project)

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1


def test_detect_multiple_credentials(tmp_path):
    """Check whether different credential types are detected."""

    project = tmp_path / "sample_project"
    project.mkdir()

    file = project / "config.yaml"
    file.write_text(
        'database_password: "MySecretPassword123"\n'
        'access_token: "AbCdEf123456789XYZ"\n'
        'client_secret: "ClientSecret987654"\n'
    )

    findings = scan_secrets(project)

    assert len(findings) == 3


def test_ignore_normal_username(tmp_path):
    """Check that a normal username is not detected."""

    project = tmp_path / "sample_project"
    project.mkdir()

    file = project / "config.yaml"
    file.write_text('username: "researcher"\n')

    findings = scan_secrets(project)

    assert len(findings) == 0


def test_finding_contains_file_and_line(tmp_path):
    """Check whether the correct file and line are reported."""

    project = tmp_path / "sample_project"
    project.mkdir()

    file = project / "pipeline.py"
    file.write_text(
        'username = "researcher"\n'
        'api_key = "ABC123XYZ987SECRET"\n'
    )

    findings = scan_secrets(project)

    assert len(findings) == 1
    assert findings[0].file == "pipeline.py"
    assert findings[0].line == 2


def test_secret_value_is_not_in_finding(tmp_path):
    """Check that the actual secret is not exposed in findings."""

    project = tmp_path / "sample_project"
    project.mkdir()

    secret = "ABC123XYZ987SECRET"

    file = project / "pipeline.py"
    file.write_text(f'api_key = "{secret}"\n')

    findings = scan_secrets(project)

    assert len(findings) == 1
    assert secret not in str(findings[0].to_dict())
