from __future__ import annotations
import logging
import sys
from typing import Any

_configured = False

def configure_logging() -> None:
    global _configured
    if _configured:
        return
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
        level=logging.DEBUG,
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    _configured = True

class _Logger:
    def __init__(self, name: str):
        self._log = logging.getLogger(name)
    def _fmt(self, event: str, **kw: Any) -> str:
        if kw:
            pairs = " ".join(f"{k}={v!r}" for k, v in kw.items())
            return f"{event} | {pairs}"
        return event
    def debug(self, event: str, **kw: Any) -> None: self._log.debug(self._fmt(event, **kw))
    def info(self, event: str, **kw: Any) -> None: self._log.info(self._fmt(event, **kw))
    def warning(self, event: str, **kw: Any) -> None: self._log.warning(self._fmt(event, **kw))
    def error(self, event: str, **kw: Any) -> None: self._log.error(self._fmt(event, **kw))
    def bind(self, **kw: Any) -> "_Logger": return self
    def __getattr__(self, name: str): return lambda *a, **kw: None

def get_logger(name: str) -> _Logger:
    return _Logger(name)

def bind_contextvars(**kw: Any) -> None: pass
def clear_contextvars() -> None: pass

class AuditLogger:
    def __init__(self): self._log = get_logger("audit")
    def log(self, event: str, **kw: Any) -> None: self._log.info(event, **kw)
