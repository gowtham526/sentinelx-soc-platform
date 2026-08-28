import requests
import time
import win32evtlog
import xml.etree.ElementTree as ET
import socket

SERVER_URL = "http://127.0.0.1:5000/ingest"
LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

seen = set()

def parse_xml(xml):
    root = ET.fromstring(xml)
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    data = {}
    for d in root.findall(".//" + ns + "Data"):
        data[d.attrib.get("Name")] = d.text
    return data

print("🌐 AGENT RUNNING...")

while True:
    try:
        handle = win32evtlog.EvtQuery(
            LOG_NAME,
            win32evtlog.EvtQueryReverseDirection,
            "*"
        )

        events = win32evtlog.EvtNext(handle, 10)

        for event in events:
            xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

            try:
                root = ET.fromstring(xml)
                ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"

                record_id = root.find(".//" + ns + "EventRecordID").text

                if record_id in seen:
                    continue
                seen.add(record_id)

                event_id = int(root.find(".//" + ns + "EventID").text)
                data = parse_xml(xml)

                if event_id == 11:
                    filename = str(data.get("TargetFilename", "")).lower()

                    # ✅ FILTER
                    if not filename.endswith(".exe"):
                        continue
                    if not ("temp" in filename or "appdata" in filename):
                        continue
                    if "prefetch" in filename:
                        continue

                    payload = {
                        "file": data.get("TargetFilename"),
                        "host": socket.gethostname(),
                        "user": data.get("User", "remote")
                    }

                    requests.post(SERVER_URL, json=payload)

            except:
                pass

    except:
        pass

    time.sleep(2)