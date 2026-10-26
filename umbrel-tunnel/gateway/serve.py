"""Production entrypoint for the Umbrel gateway.

Waitress is a small, pure-Python WSGI server. It avoids Flask's development
server warnings and gives predictable behavior behind Umbrel's app proxy.
"""

from __future__ import annotations

import os
import threading

from waitress import serve

import app as gateway


def main() -> None:
    port = int(os.environ.get("PORT", "8081"))
    threads = int(os.environ.get("WAITRESS_THREADS", "8"))
    gateway.startup()
    threading.Thread(target=gateway.background_sync, daemon=True).start()
    serve(
        gateway.app,
        host="0.0.0.0",
        port=port,
        threads=threads,
        channel_timeout=60,
        connection_limit=100,
        ident="umbrel-tunnel",
    )


if __name__ == "__main__":
    main()
