import os
from pathlib import Path
from flask import Flask, render_template, abort, jsonify
import markdown as md

APP_DIR = Path(__file__).resolve().parent
CONTENT_DIR = (APP_DIR / ".." / "content").resolve()

ERA_ORDER = ["prehistoric", "medieval", "modern", "future"]
ERA_TITLES = {
    "prehistoric": "Pre‑Historic",
    "medieval": "Medieval",
    "modern": "Modern",
    "future": "Future",
}

# Markdown renderer with sane extensions
_MD = md.Markdown(
    extensions=[
        "fenced_code",
        "codehilite",
        "tables",
        "toc",
        "sane_lists",
        "smarty",
        "nl2br",
    ],
    extension_configs={
        "codehilite": {"guess_lang": False, "css_class": "codehilite"},
    },
)

def _read_md(era: str) -> str:
    if era not in ERA_TITLES:
        abort(404)
    p = CONTENT_DIR / f"{era}.md"
    if not p.exists():
        abort(404)
    return p.read_text(encoding="utf-8", errors="replace")

def _render_md(markdown_text: str) -> str:
    # Reset state for consistent rendering across requests
    _MD.reset()
    return _MD.convert(markdown_text)

def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    @app.get("/")
    def index():
        # default era content
        era = "prehistoric"
        html = _render_md(_read_md(era))
        return render_template(
            "index.html",
            eras=ERA_ORDER,
            titles=ERA_TITLES,
            initial_era=era,
            initial_html=html,
        )

    @app.get("/api/era/<era>")
    def api_era(era: str):
        html = _render_md(_read_md(era))
        return jsonify({"era": era, "title": ERA_TITLES[era], "html": html})

    @app.get("/healthz")
    def healthz():
        return "ok"

    return app

app = create_app()

if __name__ == "__main__":
    # Production: run with gunicorn; this is for local debug.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
