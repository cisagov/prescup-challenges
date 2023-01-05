from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI()


class Report(BaseModel):
    pass


@app.get("/ip", response_class=HTMLResponse)
async def ip(request: Request):
    client_host = request.client.host
    return f"""
    <html>
        <head>
            <title>IP Address Lookup Service</title>
        </head>
        <body>
            <h1>Your IP address is:</h1>
            <paragraph>{client_host}</paragraph>
        </body>
    </html>
    """


@app.post("/report")
async def report(_: Report):
    pass
