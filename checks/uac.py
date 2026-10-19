import json
import subprocess

from core.findings import Finding


def check_uac() -> Finding:
    # Read UAC settings from the Windows registry.
    # This operation does not modify system configuration.
    command = """
    $settings = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction Stop

    [PSCustomObject]@{
        EnableLUA = $settings.EnableLUA
        ConsentPromptBehaviorAdmin = $settings.ConsentPromptBehaviorAdmin
        PromptOnSecureDesktop = $settings.PromptOnSecureDesktop
    } | ConvertTo-Json -Compress
    """

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "UAC query failed."
            )

        settings = json.loads(result.stdout)

        # All three registry values must be valid integers.
        required = [
            "EnableLUA",
            "ConsentPromptBehaviorAdmin",
            "PromptOnSecureDesktop"
        ]

        if not isinstance(settings, dict):
            raise ValueError("Invalid UAC configuration data.")

        for key in required:
            if type(settings.get(key)) is not int:
                raise ValueError(f"Invalid UAC setting: {key}")

        if settings["EnableLUA"] not in (0, 1):
            raise ValueError("Invalid EnableLUA value.")

        if settings["ConsentPromptBehaviorAdmin"] not in range(6):
            raise ValueError("Invalid administrator consent setting.")

        if settings["PromptOnSecureDesktop"] not in (0, 1):
            raise ValueError("Invalid secure desktop setting.")

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        return Finding(
            check_id="UAC-001",
            title="User Account Control configuration",
            status="ERROR",
            severity="INFO",
            description="Unable to verify UAC configuration.",
            evidence=str(error),
            recommendation="Verify registry access and PowerShell output."
        )

    # UAC is disabled entirely.
    if settings["EnableLUA"] == 0:
        status = "FAIL"
        severity = "HIGH"
        description = "User Account Control is disabled."
        recommendation = "Enable UAC and restart Windows."

    # Administrators elevate without a consent or credential prompt.
    elif settings["ConsentPromptBehaviorAdmin"] == 0:
        status = "FAIL"
        severity = "MEDIUM"
        description = (
            "UAC is enabled, but administrator elevation "
            "does not require a prompt."
        )
        recommendation = (
            "Configure UAC to require administrator consent "
            "or credentials for elevation."
        )

    # Secure Desktop is disabled for elevation prompts.
    elif settings["PromptOnSecureDesktop"] == 0:
        status = "WARN"
        severity = "MEDIUM"
        description = (
            "UAC is enabled, but elevation prompts "
            "do not use the secure desktop."
        )
        recommendation = (
            "Enable secure desktop for UAC elevation prompts."
        )

    else:
        status = "PASS"
        severity = "INFO"
        description = (
            "UAC is enabled with elevation prompting "
            "and secure desktop configured."
        )
        recommendation = "Maintain the current UAC configuration."

    return Finding(
        check_id="UAC-001",
        title="User Account Control configuration",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps(settings),
        recommendation=recommendation
    )