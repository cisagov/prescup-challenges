
# Whats in the box?

_Challenge Artifacts_

- [setup.py](./setup.py) - Script that will insert variables into base python scripts and then obfuscate them to create files to be given to competitors. 
- [upload.py](./scripts/upload.py) - Base python script that is obfuscated by the setup.py script and then provided to the competitors during the challenge.
- [encrypt.py](./scripts/encrypt.py) - Base python script that is obfuscated by the setup.py script and then provided to the competitors during the challenge.
- [executor.py](./scripts/executor.py) - Base python script that is obfuscated by the setup.py script and then provided to the competitors during the challenge.
- [srvr.py](./scripts/srvr.py) - Base python script that is obfuscated by the setup.py script and then provided to the competitors during the challenge.
- [transfer.py](./scripts/transfer.py) - Base python script that is obfuscated by the setup.py script and then provided to the competitors during the challenge.

_Note: You will need a machine able to run python as well as the libraries used within the scripts.


_Setup_

1. Create two directories in the same location as the 'setup.py' script. These should be named:
    - `tmp`
    - `hosted_files`
2. Run the [setup.py](./setup.py) script. Once completed it will generate the five obfuscated scripts that are provided to the competitors at challenge start. 
