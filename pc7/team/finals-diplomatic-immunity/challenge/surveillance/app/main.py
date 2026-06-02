from fastapi import FastAPI
from fastapi.responses import FileResponse, PlainTextResponse

app = FastAPI()

@app.get("/list")
def list_items():
    with open("/app/data/list.txt","r") as f:
        return PlainTextResponse(f.read())

@app.get("/cctv/hallway-1.mp4")
def hallway_video():
    """Serve a short hallway CCTV clip derived from the key frame.
    The still frame (/frames/frame-003.jpg) contains the OCR-able passphrase.
    """
    return FileResponse("/app/data/cctv/hallway-1.mp4", media_type="video/mp4")

@app.get("/frames/frame-003.jpg")
def frame():
    return FileResponse("/app/data/frames/frame-003.jpg", media_type="image/jpeg")

@app.get("/artifacts/payload.cam.enc")
def payload():
    return FileResponse("/app/data/artifacts/payload.cam.enc", media_type="application/octet-stream")
