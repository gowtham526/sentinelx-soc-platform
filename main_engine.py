import sys
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except:
    pass

"""
SentinelX Master Startup Engine v4.0
Run this ONE file to start the entire platform:
    py main_engine.py

Starts: Flask Dashboard + all 10 detectors simultaneously
(PowerShell + CMD + EXE + Network + Registry + Canary + Sysmon x3 + Suricata/Wazuh)
"""

import threading
import time
import sys
import os

# ─────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────

from core.alert_pipeline import process_alert, fire

# Every detector import is guarded individually so that ONE platform-specific
# module failing to import (e.g. registry_detector's winreg on a non-Windows
# box, or any future detector added without cross-platform testing) can never
# take down Flask and the other six detectors with it. Previously only the
# sysmon imports were guarded this way — registry_detector was not, so a
# single failed import there crashed the entire process before anything
# started. Same treatment for all of them now.
_DETECTOR_IMPORT_ERRORS = {}

def _try_import(name, import_fn):
    try:
        return import_fn()
    except ImportError as e:
        _DETECTOR_IMPORT_ERRORS[name] = str(e)
        return None

monitor_exe        = _try_import("EXE Monitor",        lambda: __import__("detectors.exe_detector", fromlist=["monitor_exe"]).monitor_exe)
monitor_network    = _try_import("Network Monitor",    lambda: __import__("detectors.network_detector", fromlist=["monitor_network"]).monitor_network)
monitor_powershell = _try_import("PowerShell Monitor", lambda: __import__("detectors.powershell_detector", fromlist=["monitor_powershell"]).monitor_powershell)
monitor_cmd        = _try_import("CMD Monitor",        lambda: __import__("detectors.cmd_detector",         fromlist=["monitor_cmd"]).monitor_cmd)
monitor_registry   = _try_import("Registry Monitor",   lambda: __import__("detectors.registry_detector", fromlist=["monitor_registry"]).monitor_registry)

# Canary/honeytoken detector exports two independent monitors — decoy files
# (watchdog, cross-platform) and decoy account (win32evtlog, Windows-only).
# Imported separately, same as the four above, so one being unavailable
# (e.g. no pywin32 on this box) never takes the other down with it.
monitor_canary_files   = _try_import("Canary File Monitor",    lambda: __import__("detectors.canary_detector", fromlist=["monitor_canary_files"]).monitor_canary_files)
monitor_canary_account = _try_import("Canary Account Monitor", lambda: __import__("detectors.canary_detector", fromlist=["monitor_canary_account"]).monitor_canary_account)
monitor_cmdhistory     = _try_import("CmdHistory Monitor",     lambda: __import__("detectors.cmdhistory_detector", fromlist=["monitor_cmdhistory"]).monitor_cmdhistory)
monitor_universal      = _try_import("Universal Scanner",      lambda: __import__("detectors.universal_detector", fromlist=["monitor_universal"]).monitor_universal)

SYSMON_AVAILABLE = True
try:
    from detectors.sysmon_detector         import monitor_sysmon
    from detectors.sysmon_file_detector    import monitor_sysmon_file
    from detectors.sysmon_network_detector import monitor_sysmon_network
except ImportError:
    SYSMON_AVAILABLE = False

# Optional external-sensor connectors (Suricata / Wazuh). Each is fully
# self-contained: if not configured in .env, its monitor_* function returns
# immediately with a clear one-line message instead of erroring, and if the
# module can't even be imported (e.g. missing optional dependency) it's
# skipped the same defensive way as every detector above.
SURICATA_AVAILABLE = True
try:
    from integrations.suricata_connector import monitor_suricata
except ImportError as e:
    SURICATA_AVAILABLE = False
    _DETECTOR_IMPORT_ERRORS["Suricata Connector"] = str(e)

WAZUH_AVAILABLE = True
try:
    from integrations.wazuh_connector import monitor_wazuh
except ImportError as e:
    WAZUH_AVAILABLE = False
    _DETECTOR_IMPORT_ERRORS["Wazuh Connector"] = str(e)

FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_URL  = "http://127.0.0.1:" + str(FLASK_PORT)


def print_banner():
    print()
    print("=" * 60)
    print("  SentinelX Enterprise SOC Platform  v4.0")
    print("  Real-Time Automated Threat Detection")
    print("=" * 60)
    print("  Dashboard  ->  " + FLASK_URL)
    print()
    print("  Login:  analyst / analyst123  (SOC Analyst)")
    print("          admin   / admin123    (SOC Admin)")
    print("=" * 60)
    print("  STARTING COMPONENTS...")
    print("=" * 60)
    print()


def start_flask():
    """Start Flask dashboard in background thread."""
    try:
        import app as flask_app
        print("  [OK]  Flask Dashboard -> started on port " + str(FLASK_PORT))
        flask_app.app.run(
            host         = FLASK_HOST,
            port         = FLASK_PORT,
            debug        = False,
            use_reloader = False,
        )
    except Exception as e:
        print("  [ERR] Flask failed to start: " + str(e))


def wait_for_flask(timeout=15):
    """Wait until Flask is accepting connections."""
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.create_connection(("127.0.0.1", FLASK_PORT), timeout=1)
            s.close()
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    return False


def run_detector(name, fn, *args):
    """Run a detector with auto-restart on crash.

    A detector/connector can also exit *cleanly* (no exception) when its
    prerequisite isn't available — winreg missing, pywin32 missing,
    Suricata/Wazuh not configured in .env, etc. Without a backoff on that
    path too, this loop was spinning at zero delay, calling it again
    instantly forever (confirmed by actually running this — the log
    filled with the same "not available" line hundreds of times a
    second). Same 5s backoff now applies whether the return was clean or
    via exception.
    """
    while True:
        try:
            fn(*args)
            print("  [" + name + "] exited cleanly — retrying in 5 seconds...")
            time.sleep(5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("\n  [WARN] [" + name + "] crashed: " + str(e))
            print("         Restarting in 5 seconds...")
            time.sleep(5)


def health_monitor(detector_threads):
    """Print periodic health status every 60 seconds. Also checks for
    CRITICAL alerts still OPEN past SLA (see integrations/notifier.py) —
    piggybacking on this existing 60s loop rather than starting a whole
    separate thread just for that."""
    while True:
        time.sleep(60)
        alive = sum(1 for t in detector_threads if t.is_alive())
        total = len(detector_threads)
        ts    = time.strftime("%H:%M:%S")
        print(
            "\n  [" + ts + "] Health: "
            + str(alive) + "/" + str(total)
            + " detectors running | Dashboard: " + FLASK_URL
        )
        try:
            from integrations.notifier import escalate_check
            from core.alert_pipeline import _load, ALERT_FILE
            escalate_check(_load(ALERT_FILE))
        except Exception as e:
            print(f"  [Notifier] escalation check skipped: {e}")


def open_browser():
    """Open dashboard in default browser after 2 seconds."""
    time.sleep(2)
    try:
        import webbrowser
        webbrowser.open(FLASK_URL)
    except Exception:
        pass


def main():
    print_banner()

    # Start Flask
    flask_thread = threading.Thread(
        target = start_flask,
        name   = "FlaskDashboard",
        daemon = True,
    )
    flask_thread.start()

    print("  [..] Waiting for Flask dashboard...")
    if wait_for_flask(timeout=15):
        print("  [OK] Flask Dashboard -> " + FLASK_URL)
    else:
        print("  [??] Flask may still be starting...")

    time.sleep(1)

    # Define all detectors — only ones that actually imported successfully
    _candidates = [
        ("EXE Monitor",           monitor_exe),
        ("Network Monitor",       monitor_network),
        ("PowerShell Monitor",    monitor_powershell),
        ("CMD Monitor",           monitor_cmd),           # NEW — cmd.exe TTP detector
        ("Registry Monitor",      monitor_registry),
        ("Canary File Monitor",    monitor_canary_files),
        ("Canary Account Monitor", monitor_canary_account),
        ("CmdHistory Monitor",     monitor_cmdhistory),
        ("Universal Scanner",      monitor_universal),
    ]
    detectors = [(name, fn, (process_alert,)) for name, fn in _candidates if fn is not None]
    for name, fn in _candidates:
        if fn is None:
            print(f"  [??] {name} skipped — import failed: {_DETECTOR_IMPORT_ERRORS.get(name, 'unknown error')}")

    if SYSMON_AVAILABLE:
        detectors += [
            ("Sysmon Ancestry Monitor",  monitor_sysmon,         (process_alert,)),
            ("Sysmon File Monitor",      monitor_sysmon_file,    (process_alert,)),
            ("Sysmon Network Monitor",   monitor_sysmon_network, (process_alert,)),
        ]
    else:
        print("  [??] Sysmon detectors skipped (win32evtlog not available)")

    # Suricata & Wazuh external connectors
    suricata_configured = bool(os.environ.get("SURICATA_EVE_JSON_PATH"))
    if SURICATA_AVAILABLE and suricata_configured:
        detectors.append(("Suricata Connector", monitor_suricata, (process_alert,)))
    elif SURICATA_AVAILABLE:
        print("  [--] Suricata connector idle (SURICATA_EVE_JSON_PATH not set in .env)")
    else:
        print(f"  [??] Suricata connector skipped — {_DETECTOR_IMPORT_ERRORS.get('Suricata Connector', 'not available')}")

    wazuh_configured = bool(os.environ.get("WAZUH_INDEXER_HOST"))
    if WAZUH_AVAILABLE and wazuh_configured:
        detectors.append(("Wazuh Connector", monitor_wazuh, (process_alert,)))
    elif WAZUH_AVAILABLE:
        print("  [--] Wazuh connector idle (WAZUH_INDEXER_HOST not set in .env)")
    else:
        print(f"  [??] Wazuh connector skipped — {_DETECTOR_IMPORT_ERRORS.get('Wazuh Connector', 'not available')}")

    # IOC feeds run on their own internal refresh loop rather than the
    # run_detector() thread pattern above (it's a periodic bulk download,
    # not a continuous event stream) — started separately, once.
    try:
        from integrations.ioc_feeds import start_background_refresh
        start_background_refresh()
    except ImportError as e:
        print(f"  [??] IOC feed connector skipped — {e}")

    # Start all detectors
    print()
    print("  Starting detection monitors...")
    print()

    detector_threads = []
    for name, fn, args in detectors:
        t = threading.Thread(
            target = run_detector,
            args   = (name, fn) + args,
            name   = name,
            daemon = True,
        )
        t.start()
        detector_threads.append(t)
        print("  [OK]  " + name)
        time.sleep(0.3)

    # Health monitor
    threading.Thread(
        target = health_monitor,
        args   = (detector_threads,),
        name   = "HealthMonitor",
        daemon = True,
    ).start()

    # Open browser
    threading.Thread(target=open_browser, daemon=True).start()

    # Final status
    print()
    print("=" * 60)
    print("  SentinelX is LIVE")
    print("=" * 60)
    print("  Dashboard  ->  " + FLASK_URL)
    print("  Monitors   ->  " + str(len(detector_threads)) + " detectors active")
    print("  Refresh    ->  every 4 seconds")
    print()
    print("  Press Ctrl+C to stop all engines")
    print("=" * 60)
    print()

    # Keep alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print("=" * 60)
        print("  SentinelX shutdown requested")
        print("  All monitors stopping...")
        print("=" * 60)
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()