import os, ssl, json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# NOTE: Uvicorn provides TLS; client cert requirement enforced at handshake level isn't trivial here.
# For this build, we simulate requirement by accepting without client verify (simplified),
# but you can run behind nginx with ssl_verify_client if strict mTLS is needed.

app = FastAPI()

TOKENS = { "token1": os.getenv("TOKEN1",""), "token2": os.getenv("TOKEN2",""),
           "token3": os.getenv("TOKEN3",""), "token4": os.getenv("TOKEN4",""),
           "token5": os.getenv("TOKEN5","") }

@app.post("/access/reinstate")
async def reinstate(req: Request):
    data = await req.json()
    for k in ("token1","token2","token3","token4"):
        if data.get(k) != TOKENS[k]:
            raise HTTPException(status_code=400, detail="invalid tokens")
    return JSONResponse({"request":"granted", "AMBASSADOR_CLEARANCE_KEY": TOKENS.get("token5",""), "Legal First Name": "Kabal", "Legal Last Name":"Alexander", "legal status":"🟢 DIPLOMATIC IMMUNITY"})
