#!/usr/bin/env python3
"""Generate Sysmon + PowerShell event JSON for log-seeder.

The events reference the real SHA256 of install_obf.bat so that the
Token 1 grader's expected hash matches what's recorded in EID 1.
Output goes to events/sysmon.ndjson and events/powershell.ndjson.

Run once at challenge build time:
    python3 build_events.py --dropper ../artifact-server/payloads/install_obf.bat

The generated NDJSON files are committed to the repo; the log-seeder
just bulk-uploads them at container startup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from datetime import datetime, timezone


HOST = "eng-bell-04"
DOMAIN = "SKYLOOM"
USER = "jhowell"
SID = "S-1-5-21-1004336348-1177238915-682003330-1006"

# Two relevant timelines:
#   * Install events on 2026-04-22 — the actual compromise date.
#   * Re-activation events on 2026-05-12 02:17 — what the SOC noticed.
INSTALL_BASE = datetime(2026, 4, 22, 3, 14, 11, tzinfo=timezone.utc)
ACTIVATION_BASE = datetime(2026, 5, 12, 2, 17, 0, tzinfo=timezone.utc)


def ts(base: datetime, offset_seconds: float) -> str:
    return (
        base.replace(microsecond=int((offset_seconds % 1) * 1_000_000))
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    ) if False else _bump(base, offset_seconds).isoformat().replace("+00:00", "Z")


def _bump(base: datetime, off: float) -> datetime:
    from datetime import timedelta

    return base + timedelta(seconds=off)


def sysmon_eid1(
    *,
    base: datetime,
    offset: float,
    parent_image: str,
    parent_command_line: str,
    image: str,
    command_line: str,
    user: str = USER,
    file_hashes: dict[str, str] | None = None,
    record_id: int,
) -> dict:
    """Sysmon Event ID 1 — Process creation."""
    hashes = ""
    if file_hashes:
        hashes = ",".join(f"{k.upper()}={v}" for k, v in file_hashes.items())
    return {
        "@timestamp": _bump(base, offset).isoformat().replace("+00:00", "Z"),
        "event": {
            "code": "1",
            "provider": "Microsoft-Windows-Sysmon",
            "action": "Process Create",
            "category": ["process"],
            "type": ["start"],
        },
        "host": {"hostname": HOST, "name": HOST},
        "user": {"name": user, "domain": DOMAIN},
        "process": {
            "executable": image,
            "name": image.rsplit("\\", 1)[-1],
            "command_line": command_line,
            "parent": {
                "executable": parent_image,
                "name": parent_image.rsplit("\\", 1)[-1],
                "command_line": parent_command_line,
            },
        },
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "Image": image,
                "CommandLine": command_line,
                "ParentImage": parent_image,
                "ParentCommandLine": parent_command_line,
                "User": f"{DOMAIN}\\{user}",
                "Hashes": hashes,
                "UtcTime": _bump(base, offset).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            },
        },
    }


def sysmon_eid3(*, base: datetime, offset: float, image: str, dest_ip: str, dest_port: int, dest_hostname: str, record_id: int) -> dict:
    """Sysmon Event ID 3 — Network connection."""
    return {
        "@timestamp": _bump(base, offset).isoformat().replace("+00:00", "Z"),
        "event": {"code": "3", "provider": "Microsoft-Windows-Sysmon", "action": "Network Connect", "category": ["network"]},
        "host": {"hostname": HOST, "name": HOST},
        "user": {"name": USER, "domain": DOMAIN},
        "process": {"executable": image, "name": image.rsplit("\\", 1)[-1]},
        "destination": {"ip": dest_ip, "port": dest_port, "domain": dest_hostname},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 3,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "Image": image,
                "User": f"{DOMAIN}\\{USER}",
                "DestinationIp": dest_ip,
                "DestinationPort": dest_port,
                "DestinationHostname": dest_hostname,
                "Protocol": "tcp",
                "UtcTime": _bump(base, offset).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            },
        },
    }


def sysmon_eid11(*, base: datetime, offset: float, image: str, target_filename: str, record_id: int) -> dict:
    """Sysmon Event ID 11 — File create."""
    return {
        "@timestamp": _bump(base, offset).isoformat().replace("+00:00", "Z"),
        "event": {"code": "11", "provider": "Microsoft-Windows-Sysmon", "action": "File Created", "category": ["file"]},
        "host": {"hostname": HOST, "name": HOST},
        "user": {"name": USER, "domain": DOMAIN},
        "process": {"executable": image, "name": image.rsplit("\\", 1)[-1]},
        "file": {"path": target_filename, "name": target_filename.rsplit("\\", 1)[-1]},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 11,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "Image": image,
                "TargetFilename": target_filename,
                "User": f"{DOMAIN}\\{USER}",
                "UtcTime": _bump(base, offset).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            },
        },
    }


def sysmon_eid13(*, base: datetime, offset: float, image: str, target_object: str, details: str, record_id: int) -> dict:
    """Sysmon Event ID 13 — Registry value set."""
    return {
        "@timestamp": _bump(base, offset).isoformat().replace("+00:00", "Z"),
        "event": {"code": "13", "provider": "Microsoft-Windows-Sysmon", "action": "Registry Set", "category": ["registry"]},
        "host": {"hostname": HOST, "name": HOST},
        "user": {"name": USER, "domain": DOMAIN},
        "process": {"executable": image, "name": image.rsplit("\\", 1)[-1]},
        "registry": {"path": target_object, "data": {"strings": [details]}},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 13,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "Image": image,
                "TargetObject": target_object,
                "Details": details,
                "EventType": "SetValue",
                "User": f"{DOMAIN}\\{USER}",
                "UtcTime": _bump(base, offset).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            },
        },
    }


def sysmon_wmi(*, eid: int, base: datetime, offset: float, operation: str, name: str, consumer: str | None = None, query: str | None = None, record_id: int) -> dict:
    """Sysmon Event ID 19/20/21 — WMI filter / consumer / binding."""
    actions = {19: "WmiEventFilter", 20: "WmiEventConsumer", 21: "WmiEventBinding"}
    body = {
        "EventType": operation,
        "User": f"{DOMAIN}\\{USER}",
        "Name": name,
        "UtcTime": _bump(base, offset).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
    }
    if query is not None:
        body["Query"] = query
    if consumer is not None:
        body["Consumer"] = consumer
    return {
        "@timestamp": _bump(base, offset).isoformat().replace("+00:00", "Z"),
        "event": {"code": str(eid), "provider": "Microsoft-Windows-Sysmon", "action": actions[eid], "category": ["process"]},
        "host": {"hostname": HOST, "name": HOST},
        "user": {"name": USER, "domain": DOMAIN},
        "winlog": {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": eid,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": body,
        },
    }


def powershell_eid4104(*, base: datetime, offset: float, script_block_text: str, record_id: int) -> dict:
    """PowerShell Event ID 4104 — Script Block Logging."""
    return {
        "@timestamp": _bump(base, offset).isoformat().replace("+00:00", "Z"),
        "event": {"code": "4104", "provider": "Microsoft-Windows-PowerShell", "action": "Script Block", "category": ["process"]},
        "host": {"hostname": HOST, "name": HOST},
        "user": {"name": USER, "domain": DOMAIN},
        "winlog": {
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4104,
            "record_id": record_id,
            "computer_name": HOST,
            "event_data": {
                "ScriptBlockText": script_block_text,
                "ScriptBlockId": f"00000000-0000-0000-0000-{record_id:012d}",
                "Path": "",
            },
        },
    }


def build(dropper_path: pathlib.Path, out_dir: pathlib.Path) -> None:
    dropper_bytes = dropper_path.read_bytes()
    dropper_sha256 = hashlib.sha256(dropper_bytes).hexdigest()
    dropper_md5 = hashlib.md5(dropper_bytes).hexdigest()

    cmd_exe = r"C:\Windows\System32\cmd.exe"
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    schtasks = r"C:\Windows\System32\schtasks.exe"
    wmic = r"C:\Windows\System32\wbem\WMIC.exe"
    wscript = r"C:\Windows\System32\wscript.exe"
    python_exe = r"C:\Users\jhowell\AppData\Local\Programs\Python\Python312\python.exe"
    dropper_path_on_host = r"C:\Users\jhowell\Downloads\install_obf.bat"
    target_dir = r"C:\Users\jhowell\AppData\Local\SystemServices"
    startup_vbs = (
        r"C:\Users\jhowell\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\SystemServices.vbs"
    )

    sysmon_events: list[dict] = []
    powershell_events: list[dict] = []
    rec = 1000  # arbitrary starting record id

    # ----- INSTALL DAY (2026-04-22) ---------------------------------------

    # 1) cmd.exe launches install_obf.bat
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=0,
            parent_image=r"C:\Windows\explorer.exe",
            parent_command_line="C:\\Windows\\explorer.exe",
            image=cmd_exe,
            command_line=f'cmd.exe /c "{dropper_path_on_host}"',
            user=USER,
            file_hashes={"md5": dropper_md5, "sha256": dropper_sha256},
            record_id=rec,
        )
    )
    rec += 1

    # 2) install_obf.bat -> install_obf.bat process (the bat itself starts)
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=0.4,
            parent_image=cmd_exe,
            parent_command_line=f'cmd.exe /c "{dropper_path_on_host}"',
            image=dropper_path_on_host,
            command_line=f'"{dropper_path_on_host}"',
            file_hashes={"md5": dropper_md5, "sha256": dropper_sha256},
            record_id=rec,
        )
    )
    rec += 1

    # 3) install_obf.bat -> findstr (extracts payload bounds)
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=0.8,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=r"C:\Windows\System32\findstr.exe",
            command_line=f'findstr /n "::PAYLOAD-START::" "{dropper_path_on_host}"',
            record_id=rec,
        )
    )
    rec += 1

    # 4) install_obf.bat -> powershell (extract payload)
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=1.2,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=powershell,
            command_line=(
                f'powershell -NoProfile -Command "$src=\'{dropper_path_on_host}\'; '
                f"$dst='{target_dir}\\svc.b64'; (Get-Content -LiteralPath $src "
                f'-Encoding ASCII)[N..M] -join \'\' | Set-Content -LiteralPath $dst"'
            ),
            record_id=rec,
        )
    )
    rec += 1

    # 5) install_obf.bat -> powershell (base64 + DEFLATE decode)
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=1.6,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=powershell,
            command_line=(
                f"powershell -NoProfile -Command \"$b64=Get-Content "
                f"'{target_dir}\\svc.b64'; $bytes=[Convert]::FromBase64String($b64); "
                f"$ds=New-Object IO.Compression.DeflateStream(...); "
                f"Set-Content -LiteralPath '{target_dir}\\svc.py' -Value $text -Encoding UTF8\""
            ),
            record_id=rec,
        )
    )
    rec += 1

    # 6) Defense evasion — Set-MpPreference -DisableRealtimeMonitoring $true
    canonical_evasion_cmd = "Set-MpPreference -DisableRealtimeMonitoring $true"
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=2.1,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=powershell,
            command_line=f'powershell -NoProfile -Command "{canonical_evasion_cmd}"',
            record_id=rec,
        )
    )
    rec += 1
    powershell_events.append(
        powershell_eid4104(
            base=INSTALL_BASE,
            offset=2.15,
            script_block_text=canonical_evasion_cmd,
            record_id=rec,
        )
    )
    rec += 1

    # 7) Other Defender disablement steps
    for off, ps in [
        (2.5, f"Add-MpPreference -ExclusionPath '{target_dir}'"),
        (2.8, "Add-MpPreference -ExclusionProcess 'python.exe'"),
        (3.1, "Set-MpPreference -DisableBehaviorMonitoring $true"),
        (3.4, "Set-MpPreference -DisableIOAVProtection $true"),
        (3.7, "Set-MpPreference -DisableScriptScanning $true"),
    ]:
        sysmon_events.append(
            sysmon_eid1(
                base=INSTALL_BASE,
                offset=off,
                parent_image=dropper_path_on_host,
                parent_command_line=f'"{dropper_path_on_host}"',
                image=powershell,
                command_line=f'powershell -NoProfile -Command "{ps}"',
                record_id=rec,
            )
        )
        rec += 1
        powershell_events.append(
            powershell_eid4104(base=INSTALL_BASE, offset=off + 0.05, script_block_text=ps, record_id=rec)
        )
        rec += 1

    # 8) Registry Run key set (EID 13)
    sysmon_events.append(
        sysmon_eid13(
            base=INSTALL_BASE,
            offset=4.0,
            image=r"C:\Windows\System32\reg.exe",
            target_object=r"HKU\S-1-5-21-1004336348-1177238915-682003330-1006\Software\Microsoft\Windows\CurrentVersion\Run\SystemServices",
            details=f'wscript.exe "{startup_vbs}"',
            record_id=rec,
        )
    )
    rec += 1

    # 9) File create — Startup VBS launcher (EID 11)
    sysmon_events.append(
        sysmon_eid11(
            base=INSTALL_BASE,
            offset=4.2,
            image=cmd_exe,
            target_filename=startup_vbs,
            record_id=rec,
        )
    )
    rec += 1

    # 10) Scheduled task creation
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=4.6,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=schtasks,
            command_line=(
                f'schtasks /create /tn "\\Microsoft\\Windows\\WindowsUpdate\\SystemServicesCheck" '
                f'/tr "wscript.exe \\"{startup_vbs}\\"" /sc onlogon /rl highest /f'
            ),
            record_id=rec,
        )
    )
    rec += 1

    # 11) WMI subscription — filter, consumer, binding via wmic.exe
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=5.1,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=wmic,
            command_line=(
                'wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE '
                'Name="WindowsHealthFilter", EventNamespace="root\\cimv2", QueryLanguage="WQL", '
                'Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"'
            ),
            record_id=rec,
        )
    )
    rec += 1
    sysmon_events.append(
        sysmon_wmi(
            eid=19,
            base=INSTALL_BASE,
            offset=5.15,
            operation="WmiFilterEvent",
            name="WindowsHealthFilter",
            query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
            record_id=rec,
        )
    )
    rec += 1
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=5.5,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=wmic,
            command_line=(
                'wmic /namespace:\\\\root\\subscription PATH CommandLineEventConsumer CREATE '
                'Name="WindowsHealthMonitor", '
                f'CommandLineTemplate="wscript.exe \\"{startup_vbs}\\""'
            ),
            record_id=rec,
        )
    )
    rec += 1
    sysmon_events.append(
        sysmon_wmi(
            eid=20,
            base=INSTALL_BASE,
            offset=5.55,
            operation="WmiConsumerEvent",
            name="WindowsHealthMonitor",
            record_id=rec,
        )
    )
    rec += 1
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=5.9,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=wmic,
            command_line=(
                'wmic /namespace:\\\\root\\subscription PATH __FilterToConsumerBinding CREATE '
                'Filter="__EventFilter.Name=\\"WindowsHealthFilter\\"", '
                'Consumer="CommandLineEventConsumer.Name=\\"WindowsHealthMonitor\\""'
            ),
            record_id=rec,
        )
    )
    rec += 1
    sysmon_events.append(
        sysmon_wmi(
            eid=21,
            base=INSTALL_BASE,
            offset=5.95,
            operation="WmiBindingEvent",
            name="WindowsHealthFilter -> WindowsHealthMonitor",
            consumer="WindowsHealthMonitor",
            record_id=rec,
        )
    )
    rec += 1

    # 12) Final evasion — disable script block logging itself
    disable_sbl_cmd = (
        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
        "-Name EnableScriptBlockLogging -Value 0"
    )
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=6.5,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=powershell,
            command_line=f'powershell -NoProfile -Command "{disable_sbl_cmd}"',
            record_id=rec,
        )
    )
    rec += 1
    # NOTE: This is the LAST PowerShell EID 4104 event — after this,
    # script-block logging is off and no further 4104s exist in the
    # forensic record.
    powershell_events.append(
        powershell_eid4104(
            base=INSTALL_BASE,
            offset=6.55,
            script_block_text=disable_sbl_cmd,
            record_id=rec,
        )
    )
    rec += 1

    # 13) Launch implant (python.exe svc.py)
    sysmon_events.append(
        sysmon_eid1(
            base=INSTALL_BASE,
            offset=7.0,
            parent_image=dropper_path_on_host,
            parent_command_line=f'"{dropper_path_on_host}"',
            image=python_exe,
            command_line=f'python.exe "{target_dir}\\svc.py"',
            record_id=rec,
        )
    )
    rec += 1

    # ----- RE-ACTIVATION (2026-05-12 02:17) -------------------------------
    # The watchdog inside svc.py + the scheduled task re-launched the
    # implant; SOC noticed the burst of python.exe -> outbound TCP
    # activity at this point.

    sysmon_events.append(
        sysmon_eid1(
            base=ACTIVATION_BASE,
            offset=0,
            parent_image=wscript,
            parent_command_line=f'wscript.exe "{startup_vbs}"',
            image=python_exe,
            command_line=f'python.exe "{target_dir}\\svc.py"',
            record_id=rec,
        )
    )
    rec += 1

    sysmon_events.append(
        sysmon_eid3(
            base=ACTIVATION_BASE,
            offset=2.0,
            image=python_exe,
            dest_ip="159.65.207.62",
            dest_port=7835,
            dest_hostname="bore.pub",
            record_id=rec,
        )
    )
    rec += 1

    # ----- NOISE ----------------------------------------------------------
    # Interleave benign, plausible workstation activity around the install
    # and activation windows so the kill-chain events aren't trivially
    # isolated by time-range filtering alone.
    sysmon_noise, powershell_noise, rec = _build_noise(start_record_id=rec)
    sysmon_events.extend(sysmon_noise)
    powershell_events.extend(powershell_noise)

    # Sort each stream chronologically; ES doesn't require it but it keeps
    # the NDJSON pleasant to read during debugging.
    sysmon_events.sort(key=lambda ev: ev["@timestamp"])
    powershell_events.sort(key=lambda ev: ev["@timestamp"])

    # Write out
    out_dir.mkdir(parents=True, exist_ok=True)
    sysmon_path = out_dir / "sysmon.ndjson"
    powershell_path = out_dir / "powershell.ndjson"
    with sysmon_path.open("w", encoding="utf-8") as fh:
        for ev in sysmon_events:
            fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
    with powershell_path.open("w", encoding="utf-8") as fh:
        for ev in powershell_events:
            fh.write(json.dumps(ev, separators=(",", ":")) + "\n")

    print(f"wrote {len(sysmon_events)} sysmon events to {sysmon_path}")
    print(f"wrote {len(powershell_events)} powershell events to {powershell_path}")
    print(f"dropper SHA256 embedded in EID 1 events: {dropper_sha256}")


# ---------------------------------------------------------------------
# Noise corpus
# ---------------------------------------------------------------------


def _build_noise(start_record_id: int) -> tuple[list[dict], list[dict], int]:
    """Build a plausible benign-activity corpus to bury the kill-chain in.

    Three time windows are populated:
      * install_window:   2026-04-22 03:00 to 03:45 (around the install)
      * gap_window:       2026-04-22 04:00 to 2026-05-12 02:00 (long tail)
      * activation_window: 2026-05-12 01:45 to 02:35 (around re-activation)

    Sysmon noise covers process create (EID 1), network connect (EID 3),
    file create (EID 11), and registry set (EID 13). PowerShell noise is
    EID 4104 with mundane script blocks.
    """
    import random
    from datetime import timedelta

    rng = random.Random(20260512)  # deterministic
    rec = start_record_id + 100
    sysmon: list[dict] = []
    powershell: list[dict] = []

    # ---- Process templates -------------------------------------------
    # (parent_image, image, command_line_template, optional_user)
    routine_processes = [
        (r"C:\Windows\System32\services.exe", r"C:\Windows\System32\svchost.exe",
         "C:\\Windows\\System32\\svchost.exe -k {svchost_group}"),
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\RuntimeBroker.exe",
         "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"),
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\conhost.exe",
         "\\??\\C:\\Windows\\System32\\conhost.exe 0xffffffff -ForceV1"),
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\MoUsoCoreWorker.exe",
         "C:\\Windows\\System32\\MoUsoCoreWorker.exe -Embedding"),
        (r"C:\Windows\System32\services.exe", r"C:\Windows\System32\backgroundTaskHost.exe",
         "\"C:\\Windows\\System32\\backgroundTaskHost.exe\" -ServerName:App.AppX{guid}"),
        (r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
         r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
         "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /ua /installsource scheduler"),
        (r"C:\Program Files\Google\Update\GoogleUpdate.exe",
         r"C:\Program Files\Google\Update\GoogleUpdate.exe",
         "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\" /ua /installsource scheduler"),
    ]
    user_processes = [
        (r"C:\Windows\explorer.exe", r"C:\Users\jhowell\AppData\Local\Microsoft\Teams\current\Teams.exe",
         "\"C:\\Users\\jhowell\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe\" --type=renderer --user-data-dir=..."),
        (r"C:\Windows\explorer.exe", r"C:\Users\jhowell\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
         "\"C:\\Users\\jhowell\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"),
        (r"C:\Windows\explorer.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
         "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-pre-read-main-dll"),
        (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
         r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
         "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --type=renderer --tab-id={n}"),
        (r"C:\Windows\explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
        (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
         r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\" /recycle"),
        (r"C:\Windows\explorer.exe", r"C:\Users\jhowell\AppData\Local\Programs\Microsoft VS Code\Code.exe",
         "\"C:\\Users\\jhowell\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\""),
        (r"C:\Users\jhowell\AppData\Local\Programs\Microsoft VS Code\Code.exe",
         r"C:\Users\jhowell\AppData\Local\Programs\Microsoft VS Code\Code.exe",
         "\"C:\\Users\\jhowell\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\" --type=renderer"),
        (r"C:\Windows\explorer.exe", r"C:\Program Files (x86)\Slack\Slack.exe",
         "\"C:\\Program Files (x86)\\Slack\\Slack.exe\" --startup"),
    ]
    svchost_groups = ["netsvcs", "NetworkService", "LocalService", "LocalSystemNetworkRestricted",
                      "wsappx", "termsvcs", "DcomLaunch", "RPCSS"]

    # ---- Network destinations ----------------------------------------
    network_destinations = [
        ("13.107.42.14",   443, "graph.microsoft.com"),
        ("13.107.6.152",   443, "outlook.office365.com"),
        ("52.114.7.32",    443, "teams.microsoft.com"),
        ("204.79.197.200", 443, "www.bing.com"),
        ("142.250.80.46",  443, "www.google.com"),
        ("140.82.114.4",   443, "github.com"),
        ("3.5.78.94",      443, "slack.com"),
        ("104.16.123.96",  443, "cloudflare.com"),
        ("23.221.236.43",  443, "windowsupdate.microsoft.com"),
        ("52.182.143.211", 443, "login.microsoftonline.com"),
        ("13.107.4.50",    443, "ctldl.windowsupdate.com"),
        ("23.32.238.219",  443, "settings-win.data.microsoft.com"),
    ]

    # ---- File create destinations ------------------------------------
    file_targets = [
        r"C:\Users\jhowell\AppData\Local\Microsoft\Edge\User Data\Default\Cache\f_{n:06d}",
        r"C:\Users\jhowell\AppData\Local\Microsoft\Teams\Cache\Code Cache\{n:06d}.dat",
        r"C:\Users\jhowell\AppData\Local\Microsoft\Outlook\jhowell-skyloom.ost",
        r"C:\Users\jhowell\AppData\Roaming\Microsoft\Word\AutoRecovery save of Document{n}.asd",
        r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections.log",
        r"C:\Users\jhowell\AppData\Local\Temp\~DF{n:04X}.tmp",
        r"C:\Windows\Logs\WindowsUpdate\WindowsUpdate.{n:03d}.etl",
    ]

    # ---- Registry value sets -----------------------------------------
    registry_targets = [
        (r"HKU\S-1-5-21-1004336348-1177238915-682003330-1006\Software\Microsoft\Office\16.0\Common\UserInfo\UserName", "John Howell"),
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{guid}\ProfileName", "skyloom-corp"),
        (r"HKU\S-1-5-21-1004336348-1177238915-682003330-1006\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf\{n}", "design-review-{n}.pdf"),
        (r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}\DhcpIPAddress", "10.42.99.14"),
        (r"HKU\S-1-5-21-1004336348-1177238915-682003330-1006\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\{n}", "<binary>"),
    ]

    # ---- PowerShell mundane script blocks -----------------------------
    powershell_blocks = [
        "Get-Process | Where-Object {$_.CPU -gt 50}",
        "Import-Module Microsoft.PowerShell.Management",
        "Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version",
        "Get-ChildItem 'C:\\Users\\jhowell\\Documents' -Filter *.docx",
        "Test-NetConnection -ComputerName teams.microsoft.com -Port 443",
        "$ErrorActionPreference = 'SilentlyContinue'",
        "Get-Service | Where-Object Status -eq 'Running' | Measure-Object",
        "Get-EventLog -LogName Application -Newest 10",
        "Get-CimInstance -ClassName Win32_LogicalDisk",
        "Get-NetIPAddress | Where-Object AddressFamily -eq IPv4",
        "[System.Environment]::GetEnvironmentVariable('USERDOMAIN','User')",
        "Add-Type -AssemblyName System.Windows.Forms",
        "Get-ScheduledTask | Where-Object State -eq 'Ready' | Select-Object TaskName",
        "Get-LocalUser | Format-Table Name,Enabled,LastLogon",
        "Get-Hotfix | Sort-Object InstalledOn -Descending | Select-Object -First 5",
    ]

    def _emit_process_event(base_dt: datetime, offset_s: float, pool: list, _rec: int) -> dict:
        parent, image, cmd_tmpl = rng.choice(pool)
        cmd = cmd_tmpl.format(
            svchost_group=rng.choice(svchost_groups),
            guid=f"{rng.getrandbits(32):08x}-0000-0000-0000-000000000000",
            n=rng.randint(1, 9999),
        )
        return sysmon_eid1(
            base=base_dt,
            offset=offset_s,
            parent_image=parent,
            parent_command_line=parent,
            image=image,
            command_line=cmd,
            record_id=_rec,
        )

    def _emit_network_event(base_dt: datetime, offset_s: float, _rec: int) -> dict:
        ip, port, host = rng.choice(network_destinations)
        image = rng.choice([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Users\jhowell\AppData\Local\Microsoft\Teams\current\Teams.exe",
            r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            r"C:\Windows\System32\svchost.exe",
        ])
        return sysmon_eid3(
            base=base_dt,
            offset=offset_s,
            image=image,
            dest_ip=ip,
            dest_port=port,
            dest_hostname=host,
            record_id=_rec,
        )

    def _emit_file_event(base_dt: datetime, offset_s: float, _rec: int) -> dict:
        target = rng.choice(file_targets).format(n=rng.randint(1, 99999))
        image = rng.choice([
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Users\jhowell\AppData\Local\Microsoft\Teams\current\Teams.exe",
            r"C:\Windows\System32\svchost.exe",
        ])
        return sysmon_eid11(base=base_dt, offset=offset_s, image=image, target_filename=target, record_id=_rec)

    def _emit_registry_event(base_dt: datetime, offset_s: float, _rec: int) -> dict:
        target, details_tmpl = rng.choice(registry_targets)
        target = target.format(guid=f"{rng.getrandbits(32):08x}-0000-0000-0000-000000000000", n=rng.randint(1, 99))
        details = details_tmpl.format(n=rng.randint(1, 99))
        image = rng.choice([
            r"C:\Windows\System32\svchost.exe",
            r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            r"C:\Windows\explorer.exe",
        ])
        return sysmon_eid13(
            base=base_dt, offset=offset_s, image=image, target_object=target, details=details, record_id=_rec,
        )

    def _emit_ps_event(base_dt: datetime, offset_s: float, _rec: int) -> dict:
        return powershell_eid4104(
            base=base_dt, offset=offset_s, script_block_text=rng.choice(powershell_blocks), record_id=_rec,
        )

    # ---- INSTALL WINDOW: 2026-04-22 03:00 to 03:45 -------------------
    install_w_start = INSTALL_BASE - timedelta(minutes=14)
    install_w_end = INSTALL_BASE + timedelta(minutes=31)
    span_s = (install_w_end - install_w_start).total_seconds()
    for _ in range(550):
        off = rng.uniform(0, span_s)
        pool = user_processes if rng.random() < 0.55 else routine_processes
        sysmon.append(_emit_process_event(install_w_start, off, pool, rec)); rec += 1
    for _ in range(220):
        off = rng.uniform(0, span_s)
        sysmon.append(_emit_network_event(install_w_start, off, rec)); rec += 1
    for _ in range(160):
        off = rng.uniform(0, span_s)
        sysmon.append(_emit_file_event(install_w_start, off, rec)); rec += 1
    for _ in range(80):
        off = rng.uniform(0, span_s)
        sysmon.append(_emit_registry_event(install_w_start, off, rec)); rec += 1
    for _ in range(90):
        off = rng.uniform(0, span_s)
        powershell.append(_emit_ps_event(install_w_start, off, rec)); rec += 1

    # ---- GAP WINDOW: sparse daily snapshots --------------------------
    days = (ACTIVATION_BASE - INSTALL_BASE).days
    for day in range(1, days):
        snapshot_base = INSTALL_BASE + timedelta(days=day, hours=rng.randint(8, 18))
        for _ in range(rng.randint(20, 45)):
            off = rng.uniform(0, 3600 * 4)  # spread over 4 working hours
            pool = user_processes if rng.random() < 0.7 else routine_processes
            sysmon.append(_emit_process_event(snapshot_base, off, pool, rec)); rec += 1
        for _ in range(rng.randint(10, 25)):
            off = rng.uniform(0, 3600 * 4)
            sysmon.append(_emit_network_event(snapshot_base, off, rec)); rec += 1
        for _ in range(rng.randint(4, 10)):
            off = rng.uniform(0, 3600 * 4)
            powershell.append(_emit_ps_event(snapshot_base, off, rec)); rec += 1

    # ---- ACTIVATION WINDOW: 2026-05-12 01:45 to 02:35 ----------------
    act_w_start = ACTIVATION_BASE - timedelta(minutes=32)
    act_w_end = ACTIVATION_BASE + timedelta(minutes=18)
    span_s = (act_w_end - act_w_start).total_seconds()
    for _ in range(180):
        off = rng.uniform(0, span_s)
        # Late-night: mostly routine processes, less user activity
        pool = routine_processes if rng.random() < 0.8 else user_processes
        sysmon.append(_emit_process_event(act_w_start, off, pool, rec)); rec += 1
    for _ in range(60):
        off = rng.uniform(0, span_s)
        sysmon.append(_emit_network_event(act_w_start, off, rec)); rec += 1
    for _ in range(30):
        off = rng.uniform(0, span_s)
        sysmon.append(_emit_file_event(act_w_start, off, rec)); rec += 1
    for _ in range(15):
        off = rng.uniform(0, span_s)
        powershell.append(_emit_ps_event(act_w_start, off, rec)); rec += 1

    return sysmon, powershell, rec


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dropper", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("events"))
    args = parser.parse_args()
    build(args.dropper, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
