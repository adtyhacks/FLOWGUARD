"""ShopZone standalone service runner."""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass

from shopzone import create_app
from shopzone.config import Config

if __name__ == "__main__":
    app = create_app()
    host = os.getenv("SHOPZONE_HOST", "127.0.0.1")
    port = int(os.getenv("SHOPZONE_PORT", "5000"))
    debug = os.getenv("SHOPZONE_DEBUG", "False").lower() in ("true", "1", "yes")
    
    print(f"[*] Starting ShopZone on http://{host}:{port}")
    print(f"[*] Vulnerable mode prefix: http://{host}:{port}/vuln/api")
    print(f"[*] Secure mode prefix:     http://{host}:{port}/sec/api")
    print(f"[*] Admin key configured:   {'YES' if Config.ADMIN_KEY else 'NO'}")
    
    app.run(host=host, port=port, debug=debug)
