"""Start the Leengate platform:  python run.py   ->  http://127.0.0.1:5000"""
from backend import create_app

app = create_app()

if __name__ == "__main__":
    # For production use a real server instead:  gunicorn "run:app" -b 0.0.0.0:8000
    # threaded=True matters here: the frontend fires a dozen or so requests in parallel
    # right after sign-in, and Flask's dev server is single-threaded by default.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
