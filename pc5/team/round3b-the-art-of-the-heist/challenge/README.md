# The Art of the Heist

_Challenge Artifacts_

- [vault/app.py](./vault/app.py) -- Executing this file with `python3 app.py` handles running the `vault` website. All other files in the folder are required for the website to operate.
- [shiamzu/app.py](./shiamazu/app.py) -- Executing this file with `python3 app.py` handles running the `shiamazu` website. All other files in the folder are required for the website to operate.
- [canello/app.py](./canello/app.py) -- Executing this file with `python3 app.py` handles running the `canello` website. All other files in the folder are required for the website to operate.
- [tkretts/mm_get.py](./tkretts/mm_get.py) -- Script that is running on `tkretts` VM and handles making `GET` requests to `chat.merch.codes/v4/api` (mattermost API).
- [monitor/monitor.py](./monitor/monitor.py) --  Script that is running on monitor VM, checks current logged-in sessions on vault.merch.codes and terminates any sessions found to be unauthorized.
- [instructions.txt](./instructions.txt) -- Provides information to the competitors.
