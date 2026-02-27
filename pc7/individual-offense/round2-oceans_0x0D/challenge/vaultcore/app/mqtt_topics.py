# challenge/vaultcore/app/mqtt_topics.py

def telemetry(path: str) -> str:
    return f"telemetry/{path.lstrip('/')}"


def meta(path: str) -> str:
    return f"telemetry/_meta/{path.lstrip('/')}"
