"""Start the VulnWatch dashboard: python run.py  (then open http://127.0.0.1:8000)"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.web:app", host="127.0.0.1", port=8000)
