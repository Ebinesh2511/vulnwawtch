"""Start the VulnWatch dashboard: python run.py, then open http://127.0.0.1:8000.
PORT=8001 python run.py for another port; HOST=0.0.0.0 inside a container (put a login in front first)."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.web:app", host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
