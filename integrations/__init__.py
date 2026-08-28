"""
SentinelX external sensor integrations.

Each connector in this package follows the exact same interface as the
detectors in detectors/: a monitor_<name>(alert_callback) function that
main_engine.py starts as a daemon thread, feeding into the same
core.alert_pipeline.process_alert() pipeline everything else uses. That
means every alert from Suricata or Wazuh gets the same MITRE mapping,
threat-intel enrichment, severity scoring, correlation, and case/incident
logic as an alert from any built-in detector — nothing about the rest of
the app needs to know or care where the alert originated.

Both connectors are self-configuring: if their required .env settings
aren't present, they print one clear line explaining that and return
immediately rather than raising. It's always safe to import and start
them even if the user hasn't set either one up yet.
"""
