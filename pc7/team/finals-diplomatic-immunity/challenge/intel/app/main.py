from fastapi import FastAPI
from fastapi.responses import FileResponse
import os

app = FastAPI()

DATA_DIR = os.getenv("DATA_DIR", "/app/data")

@app.get("/mail/ops.mbox")
def mbox():
    path = os.path.join(DATA_DIR, "ops.mbox")
    return FileResponse(path, media_type="application/mbox")

@app.get("/ca/gost-ca.pem")
def ca():
    path = os.path.join(DATA_DIR, "ca/gost-ca.pem")
    return FileResponse(path, media_type="application/x-pem-file")
