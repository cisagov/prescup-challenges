# ...The Code is Coming from Inside the Network

_Challenge Artifacts_

[py-interpreter](./py-interpreter/)
- [Dockerfile](./py-interpreter/Dockerfile) - File used when creating the Docker Image.
- [requirements.txt](./py-interpreter/requirements.txt) - File used to specify the libraries that need to get installed when the Docker Image is getting created.
- [server.py](./py-interpreter/server.py) - Python script that is implemented in the Docker container that handles running the Python Interpreter.

[repo-api](./repo-api/)
- [insert.py](./repo-api/insert.py) - File used during startup by the Challenge Server to insert the token into the project they are searching for within the `app.db` file.
- [app.py](./repo-api/flask_app/app.py) - File that handles running the flask API. All other files in this folder are required to run the API.
- [app.db](./repo-api/flask_app/app.db) - SQLite3 Database that is used by the API to store data.

[website](./website/)
- [insert.py](./website/insert.py) - File used during startup by the Challenge Server to insert the `get` and `post` tokens into the `app.db` file.
- [upload_reset.py](./website/upload_reset.py) - File that is used during the challenge so that if a user wishes to reset the website back to its default code they can. Also is a backup file to handle uploading the website source code back to the repo if it is needed.
- [app.py](./website/flask_app/app.py) - File that handles running the flask website. All other files in this folder are required to run the website.
- [app.db](./website/flask_app/app.db) - SQLite3 Database that is used by the website to store data.
