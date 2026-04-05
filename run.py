"""Entry point for the NetCaster web application."""

import uvicorn

from webapp.app import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run("run:app", host="0.0.0.0", port=8000, reload=True)
