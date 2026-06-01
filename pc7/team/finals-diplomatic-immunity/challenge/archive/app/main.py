from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import os

app = FastAPI()

DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))

PUBLIC_ARTIFACTS = {
    "sym.key.rsa-oaep": {
        "media_type": "application/octet-stream",
        "description": "RSA wrapped symmetric key",
    },
    "classified.tar.enc": {
        "media_type": "application/octet-stream",
        "description": "AES-256-CBC encrypted classified archive",
    },
    "classified.iv": {
        "media_type": "text/plain",
        "description": "Initialization vector for archive decryption",
    },
    # Keep this endpoint if you still need backward compatibility,
    # but do not include it in the public index unless intentional.
    "classified.tag": {
        "media_type": "application/octet-stream",
        "description": "Auxiliary artifact",
    },
}


def check(h: str, envname: str) -> bool:
    return h == os.getenv(envname, "")


def require_token(x_frag: str | None, envname: str) -> None:
    if not x_frag or not check(x_frag, envname):
        raise HTTPException(status_code=403, detail="forbidden")


def send_file(path: Path, media_type: str, filename: str | None = None) -> FileResponse:
    if not path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(
        path=path,
        media_type=media_type,
        filename=filename or path.name,
    )


@app.get("/export/shareA")
def shareA(x_frag: str = Header(None)):
    require_token(x_frag, "TOKEN1")
    return send_file(
        DATA_DIR / "export" / "shareA.bin",
        media_type="application/octet-stream",
        filename="shareA.bin",
    )


@app.get("/export/shareB")
def shareB(x_frag: str = Header(None)):
    require_token(x_frag, "TOKEN2")
    return send_file(
        DATA_DIR / "export" / "shareB.bin",
        media_type="application/octet-stream",
        filename="shareB.bin",
    )


@app.get("/export/shareC")
def shareC(x_frag: str = Header(None)):
    require_token(x_frag, "TOKEN3")
    return send_file(
        DATA_DIR / "export" / "shareC.bin",
        media_type="application/octet-stream",
        filename="shareC.bin",
    )


@app.get("/artifacts")
def list_artifacts():
    visible = ["sym.key.rsa-oaep", "classified.tar.enc", "classified.iv"]

    artifacts = []
    for name in visible:
        path = DATA_DIR / "artifacts" / name
        if path.is_file():
            artifacts.append(
                {
                    "name": name,
                    "path": f"/artifacts/{name}",
                    "description": PUBLIC_ARTIFACTS[name]["description"],
                    "media_type": PUBLIC_ARTIFACTS[name]["media_type"],
                    "size_bytes": path.stat().st_size,
                }
            )

    return {
        "artifacts": artifacts,
        "count": len(artifacts),
    }


@app.get("/artifacts/{artifact_name}")
def get_artifact(artifact_name: str):
    if artifact_name not in PUBLIC_ARTIFACTS:
        raise HTTPException(status_code=404, detail="artifact not found")

    path = DATA_DIR / "artifacts" / artifact_name
    return send_file(
        path,
        media_type=PUBLIC_ARTIFACTS[artifact_name]["media_type"],
        filename=artifact_name,
    )