# Operation Juliett Whiskey Tango

_Server Setup_

1. An Ubuntu, Debian, or Mint VM is recommended for following these instructions.
2. There are several ways to create a virtual environment, but we will use [pyenv](https://github.com/pyenv/pyenv#installation) and [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv#installing-as-a-pyenv-plugin) for these instructions. Follow the linked installation instructions before continuing. Be sure to install the [suggested build environment](https://github.com/pyenv/pyenv/wiki#suggested-build-environment) as well.
3. Once pyenv is installed, run `pyenv install 3.10.9`.
4. `pyenv global 3.10.9`
5. `cd webapp`
6. `pyenv virtualenv operation_jwt`
7. `pyenv local operation_jwt`
8. `pip install -r requirements.txt`
9. `uvicorn main:app`

If you get the message "Uvicorn running on http://127.0.0.1:8000", the server is running.
