import json
import subprocess

from core.findings import Finding


# Windows chassis types associated with portable devices.
PORTABLE_CHASSIS = {8, 9, 10, 11, 12, 14, 30, 31, 32}

# Common desktop chassis types.
DESKTOP_CHASSIS = {3, 4, 5, 6, 7, 13, 15, 16, 24, 35, 36}


def classify_device(data: dict) -> str:
    """
    Classify the computer using Windows hardware information.

    Virtual machines are identified separately because their
    reported chassis type may not represent physical hardware.
    """

    manufacturer = data["Manufacturer"].lower()
    model = data["Model"].lower()
    chassis_types = data["ChassisTypes"]
    pc_type = data["PCSystemType"]

    # Common virtualization platform identifiers.
    vm_identifiers = (
        "virtual machine",
        "virtualbox",
        "vmware",
        "qemu",
        "kvm",
        "hyper-v",
        "parallels",
    )

    if any(
        identifier in manufacturer or identifier in model
        for identifier in vm_identifiers
    ):
        return "Virtual Machine"

    # Chassis information takes priority for physical devices.
    if any(code in PORTABLE_CHASSIS for code in chassis_types):
        return "Portable"

    if any(code in DESKTOP_CHASSIS for code in chassis_types):
        return "Desktop"

    # PCSystemType provides an additional classification source.
    # 1 = Desktop, 2 = Mobile, 3 = Workstation,
    # 4 = Enterprise Server, 5 = SOHO Server, 7 = Performance Server.
    if pc_type == 2:
        return "Portable"

    if pc_type in (4, 5, 7):
        return "Server"

    if pc_type in (1, 3):
        return "Desktop"

    return "Unknown"


def check_system() -> Finding:
    # Collect hardware details without changing Windows settings.
    command = r"""
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $enclosure = Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop

    [PSCustomObject]@{
        Manufacturer = [string]$computer.Manufacturer
        Model = [string]$computer.Model
        PCSystemType = [int]$computer.PCSystemType
        ChassisTypes = @($enclosure.ChassisTypes | ForEach-Object { [int]$_ })
    } | ConvertTo-Json -Compress -Depth 3
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
                result.stderr.strip() or "Hardware query failed."
            )

        data = json.loads(result.stdout)

        # Validate Windows output before using it.
        if not isinstance(data, dict):
            raise ValueError("Invalid hardware information.")

        for key in ("Manufacturer", "Model"):
            if not isinstance(data.get(key), str):
                raise ValueError(f"Invalid hardware field: {key}")

        if type(data.get("PCSystemType")) is not int:
            raise ValueError("Invalid PCSystemType.")

        chassis = data.get("ChassisTypes")

        if not isinstance(chassis, list):
            raise ValueError("Invalid chassis information.")

        if not all(type(code) is int for code in chassis):
            raise ValueError("Invalid chassis type code.")

        device_type = classify_device(data)

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:
        return Finding(
            check_id="SYS-001",
            title="Device classification",
            status="ERROR",
            severity="INFO",
            description="Unable to classify the Windows device.",
            evidence=str(error),
            recommendation="Verify access to Windows CIM hardware information."
        )

    return Finding(
        check_id="SYS-001",
        title="Device classification",
        status="PASS" if device_type != "Unknown" else "WARN",
        severity="INFO",
        description=f"Device classified as: {device_type}.",
        evidence=json.dumps({
            "device_type": device_type,
            "manufacturer": data["Manufacturer"],
            "model": data["Model"],
            "pc_system_type": data["PCSystemType"],
            "chassis_types": data["ChassisTypes"]
        }),
        recommendation=(
            "Use device classification when evaluating "
            "context-dependent security risks."
        )
    )