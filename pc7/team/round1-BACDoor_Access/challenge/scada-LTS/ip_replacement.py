import os
import sys
import zipfile
import logging
import socket
import resolver_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ZIP_FILE = "/export.zip"
TEMP_ZIP_FILE = "/export.zip.zip.tmp"
TARGET_NAME = "json_project.txt"

all_hosts = resolver_client.wait_for_complete_list()

# ----- define all placeholder -> IP mappings here -----
# Note that engineering_net IP for Lecture devices is actually in the lecture subnet
REPLACEMENTS = {
    "LECTURE_LIGHTS_IP": all_hosts["lecturelights.pccc"]["engineering_net"],
    "LECTURE_HVAC_IP": all_hosts["lecturehvac.pccc"]["engineering_net"],
    "ENGINEERING_LIGHTS_IP": all_hosts["englights.pccc"]["engineering_net"],
    "ENGINEERING_HVAC_IP": all_hosts["enghvac.pccc"]["engineering_net"],
    "ENGINEERING_SECURITY_IP": all_hosts["security.pccc"]["engineering_net"],
    "ENGINEERING_FIRE_IP": all_hosts["firesafety.pccc"]["engineering_net"],
    "ENGINEERING_POWER_IP": all_hosts["powermonitoring.pccc"]["engineering_net"],
    "ENGINEERING_WEATHER_IP": all_hosts["weather.pccc"]["engineering_net"],
    "ENGINEERING_SERVER_IP": all_hosts["serverroom.pccc"]["engineering_net"],
    "LECTURE_EV_IP": all_hosts["evcharging.pccc"]["engineering_net"],
}

logger.info("Resolved IPs: %s", list(REPLACEMENTS.items()))

# ----- read original json_project.txt from ZIP -----
with zipfile.ZipFile(ZIP_FILE, "r") as zf:
    try:
        content = zf.read(TARGET_NAME).decode("utf-8")
    except KeyError:
        raise FileNotFoundError(f"{TARGET_NAME} not found in {ZIP_FILE}")

# ----- apply all replacements -----
for placeholder, value in REPLACEMENTS.items():
    content = content.replace(placeholder, value)

# ----- rebuild ZIP cleanly with updated json_project.txt -----
with zipfile.ZipFile(ZIP_FILE, "r") as src, \
     zipfile.ZipFile(TEMP_ZIP_FILE, "w", compression=zipfile.ZIP_DEFLATED) as dst:
    for item in src.infolist():
        if item.filename == TARGET_NAME:
            # write updated content instead of original
            dst.writestr(item, content.encode("utf-8"))
        else:
            dst.writestr(item, src.read(item.filename))

# atomically replace original ZIP
os.replace(TEMP_ZIP_FILE, ZIP_FILE)
logger.info("Updated %s in %s with new IP values", TARGET_NAME, ZIP_FILE)