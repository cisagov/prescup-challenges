import logging, sys
from pythonjsonlogger import jsonlogger

def setup_logging(level: str, json_mode: bool) -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    handler = logging.StreamHandler(sys.stdout)
    if json_mode:
        fmt = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s",
                                       rename_fields={"levelname":"level","name":"logger"})
    else:
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(fmt)
    root.handlers = [handler]
