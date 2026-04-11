import os
import traceback
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime

# ── App Config ──────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///notes.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ── Models ───────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    content = db.Column(db.Text)
    category = db.Column(db.String(50))
    pinned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "category": self.category,
            "pinned": self.pinned,
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M")
        }

# ── Helpers ──────────────────────────────────────────────────

def error(msg, code=400):
    return jsonify({"success": False, "error": msg}), code

def success(data, code=200):
    return jsonify({"success": True, **data}), code

# ── Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True)

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return error("Missing fields")

    if User.query.filter_by(username=username).first():
        return error("User already exists")

    user = User(username=username, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    return success({"message": "Registered successfully"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)

    user = User.query.filter_by(username=data.get("username")).first()

    if not user or not check_password_hash(user.password, data.get("password")):
        return error("Invalid credentials", 401)

    token = create_access_token(identity=str(user.id))

    return success({"access_token": token, "username": user.username})

# ── Notes ───────────────────────────────────────────────────

@app.route("/add-note", methods=["POST"])
@jwt_required()
def add_note():
    try:
        uid = int(get_jwt_identity())
        data = request.get_json(force=True)

        if not data:
            return error("No data received")

        content = (data.get("content") or "").strip()
        if not content:
            return error("Content required")

        note = Note(
            title=(data.get("title") or "Untitled"),
            content=content,
            category=(data.get("category") or "General"),
            pinned=bool(data.get("pinned", False)),
            user_id=uid
        )

        db.session.add(note)
        db.session.commit()

        return success({"note": note.to_dict()}, 201)

    except Exception:
        import traceback
        print(traceback.format_exc())
        return error("Server error", 500)

@app.route("/notes/categories", methods=["GET"])
@jwt_required()
def get_categories():
    try:
        uid = int(get_jwt_identity())

        cats = db.session.query(Note.category).filter_by(user_id=uid).distinct().all()

        return success({
            "categories": [c[0] for c in cats]
        })

    except Exception:
        import traceback
        print(traceback.format_exc())
        return error("Server error", 500)


@app.route("/notes", methods=["GET"])
@jwt_required()
def get_notes():
    try:
        uid = int(get_jwt_identity())

        notes = Note.query.filter_by(user_id=uid).all()

        return success({
            "notes": [n.to_dict() for n in notes],
            "total": len(notes),
            "page": 1,
            "pages": 1
        })

    except Exception:
        import traceback
        print(traceback.format_exc())
        return error("Server error", 500)    

@app.route("/delete-note/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_note(id):
    uid = int(get_jwt_identity())

    note = Note.query.get(id)

    if not note or note.user_id != uid:
        return error("Not allowed")

    db.session.delete(note)
    db.session.commit()

    return success({"message": "Deleted"})

@app.route("/update-note/<int:note_id>", methods=["PUT"])
@jwt_required()
def update_note(note_id):
    try:
        uid = int(get_jwt_identity())

        note = Note.query.get(note_id)

        if not note:
            return error("Note not found", 404)

        if note.user_id != uid:
            return error("Permission denied", 403)

        data = request.get_json(force=True)

        if not data:
            return error("No data provided")

        # ✅ Safe updates
        if "title" in data:
            note.title = (data.get("title") or "Untitled").strip()

        if "content" in data:
            content = (data.get("content") or "").strip()
            if not content:
                return error("Content cannot be empty")
            note.content = content

        if "category" in data:
            note.category = (data.get("category") or "General").strip()

        if "pinned" in data:
            note.pinned = bool(data.get("pinned"))

        note.updated_at = datetime.utcnow()

        db.session.commit()

        return success({
            "message": "Note updated",
            "note": note.to_dict()
        })

    except Exception:
        import traceback
        print(traceback.format_exc())
        return error("Server error", 500)

# ── JWT Errors ───────────────────────────────────────────────

@jwt.unauthorized_loader
def missing_token(e):
    return error("Token missing", 401)

@jwt.invalid_token_loader
def invalid_token(e):
    return error("Invalid token", 401)

# ── Init ─────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)