
# Moving Day

_Challenge Artifacts_

- [adminSite](./satellite-system/adminSite/) - Folder containing all the files required to run the admin site that users interact with during this challenge.
- [satellite](./satellite-system/satellite/) - Folder containing all the files required to run the satellite that users interact with during this challenge.
- [adminSite.service](./satellite-system/adminSite.service) - Systemd service file that handles running the admin site.
- [satellite.service](./satellite-system/satellite.service) - Systemd service file that handles running the satellite.
- [finalcheck.py](./finalCheck.py) - Runs the final grading check to verify user has shutdown satellite and completed challenge.


_Setup_

1. Only one Linux machine is needed to run the admin site and satellite. This machine must have the IP `123.45.67.100` and `python3` must be installed.
2. Run the [adminSite](./satellite-system/adminSite/adminSite.py):
```bash
cd satellite-system/adminSite
python3 adminSite.py
```
3. Run the [satellite](./satellite-system/satellite/satellite.py):
```bash
cd satellite-system/satellite
python3 satellite.py
```