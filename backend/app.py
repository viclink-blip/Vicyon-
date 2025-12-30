# app.py
from flask import Flask, request, jsonify,session
from flask_jwt_extended import decode_token
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import os
import secrets
import socket
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import random
import string
from datetime import datetime, timedelta
from functools import wraps
from models import User
from engine import start_engine, get_engine, is_engine_active, engine
# App config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "viclink.db")
app = Flask(__name__, static_folder="frontend/assets", static_url_path="/assets")
plans = {}
users = {}
app.config["JWT_SECRET_KEY"] = "super-secret-key"
jwt = JWTManager(app)
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:8888", "http://localhost:8888"])
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///viclink.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "supersecretkey"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_PATH"] = "/"
db = SQLAlchemy(app)
# Models
class Plan(db.Model):

    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    max_receivers = db.Column(db.Integer, nullable=False)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200),unique=True, nullable=False)
    user_id = db.Column(db.String(5), unique=True, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    internet_status = db.Column(db.Boolean, default=True)
class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(10),
db.ForeignKey("user.user_id"), nullable=False)
    receiver_id = db.Column(db.String(10),
db.ForeignKey("user.user_id"), nullable=False)
    status = db.Column(db.String(30), default="pending")
class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # User B (who accepted)
    owner_id = db.Column(db.String(5), nullable=False)

    # User A (who is using internet)
    receiver_id = db.Column(db.String(5), nullable=False)

    # Engine session token
    token = db.Column(db.String(64), unique=True, nullable=False)

    # Fixed expiry time
    expires_at = db.Column(db.DateTime, nullable=False)

    active = db.Column(db.Boolean, default=True)
# Helpers
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from header
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing!"}), 401

        try:
            # Decode token
            decoded_token = decode_token(token)
            user_id = decoded_token.get("sub")

            # Get user from database
            current_user = User.query.get(user_id)
            if not current_user:
                return jsonify({"error": "User not found!"}), 404

            # ✅ Only update last_seen AFTER loading user
            current_user.last_seen = datetime.utcnow()
            db.session.commit()

        except Exception as e:
            return jsonify({"error": "Invalid token", "details": str(e)}), 401

        # ✅ Pass current_user to the route
        return f(current_user, *args, **kwargs)

    return decorated
# Auth Routes
def generate_user_id(existing_ids):
    """Generate a unique 5-character alphanumeric user ID."""
    while True:
        new_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        if new_id not in existing_ids:
            return new_id
@app.route('/whoami', methods=['GET'])
@jwt_required()  # ✅ use this built-in decorator
def whoami():
    user_id = get_jwt_identity()  # extract user id
    user = User.query.get(user_id)

    if not user:
        return jsonify({"logged_in": False, "error": "User not found"}), 404

    return jsonify({
        "logged_in": True,
        "user_id": user.user_id,
        "username": user.username
    }), 200
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password required"}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Account already exists"}), 409

    # 🔹 Generate a unique 5-letter/number user_id
    existing_ids = [user.user_id for user in User.query.all()]
    user_id = generate_user_id(existing_ids)

    hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")

    # 🔹 Add user_id when creating the user
    new_user = User(username=username, email=email, password=hashed_pw, user_id=user_id)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "Account created successfully!",
        "username": username,
        "user_id": user_id
    }), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid password"}), 401

    # Generate JWT Token valid for 12 hours
    token = create_access_token(identity=user.id)

    return jsonify({
        "message": "login successful",
        "redirect": "dashboard.html",
        "token": token,
        "user_id": user.user_id,
        "username": user.username
    })
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return jsonify({"message": "You have been logged out successfully.!"})
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")
    new_password = data.get("new_password")
    if not email or not new_password:
        return jsonify({"error": "Email is required"}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
       return jsonify({"error": "User not found"}), 400
    user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
    db.session.commit()
    return jsonify({"message": "password updated successfully"}), 200
@app.route("/buy_plan", methods=["POST"])
@token_required
def buy_plan(current_user):
    data = request.get_json()
    plan_type = data.get("plan_type")

    if not plan_type:
        return jsonify({"error": "plan_type is required"}), 400

    if plan_type not in ["personal", "friends"]:
        return jsonify({"error": "Invalid plan type"}), 400

    start_date = datetime.now()
    expiry_date = start_date + timedelta(days=30)

    # Store or simulate plan purchase
    plans[current_user.username] = {
        "plan": plan_type,
        "expiry_date": expiry_date
    }

    return jsonify({
        "message": f"Payment successful for {plan_type} plan!",
        "username": current_user.username,
        "plan": plan_type,
        "start_date": start_date.strftime("%Y-%m-%d"),
        "expiry_date": expiry_date.strftime("%Y-%m-%d")
    }), 200
# Connection Routes
@app.route("/connection/request/<string:receiver_user_id>", methods=["POST"])
@token_required
def send_connection_request(current_user, receiver_user_id):
    # Find receiver by their custom user_id
    receiver = User.query.filter_by(user_id=receiver_user_id).first()
    if not receiver:
        return jsonify({"error": "Receiver not found"}), 404

    # Check if request already exists
    existing = Connection.query.filter_by(sender_id=current_user.id, receiver_id=receiver.id).first()
    if existing:
        return jsonify({"error": "Request already sent"}), 400

    # Create connection
    connection = Connection(sender_id=current_user.id, receiver_id=receiver.id)
    db.session.add(connection)
    db.session.commit()

    return jsonify({"message": "Connection request sent!"}), 201

@app.route("/connection/incoming", methods=["GET"])
@app.route("/connection/incoming/<string:sender_user_id>", methods=["GET"])
@token_required
def incoming_requests(current_user, sender_user_id=None):
    # Start with all requests where current user is the receiver
    query = Connection.query.filter_by(receiver_id=current_user.id)

    # Optional filter by sender's custom user_id
    if sender_user_id:
        sender = User.query.filter_by(user_id=sender_user_id).first()
        if sender:
            query = query.filter_by(sender_id=sender.id)

    requests = query.all()

    return jsonify([
        {
            "id": r.id,
            "from_user_id": User.query.get(r.sender_id).user_id,
            "status": r.status
        } for r in requests
    ])
@app.route("/connection/accept/<string:sender_id>", methods=["POST"])
@token_required
def accept_request(current_user, sender_id):
    # Try to find the sender using their unique alphanumeric ID (the one returned at signup)
    sender = User.query.filter_by(user_id=sender_id).first()

    # If not found, maybe your table uses plain numeric id instead
    if not sender:
        try:
            sender = User.query.get(int(sender_id))
        except ValueError:
            sender = None

    if not sender:
        return jsonify({"error": "Sender not found"}), 404

    # Find the pending connection request
    connection = Connection.query.filter_by(
        sender_id=sender.id,
        receiver_id=current_user.id,
        status="pending"
    ).first()

    if not connection:
        return jsonify({"error": "No pending request found"}), 404

    # Accept the connection
    connection.status = "accepted"
    # ================= ENGINE START =================

    engine_token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(minutes=30)

    engine_session = Session(
    owner_id=current_user.user_id,   # User B
    receiver_id=sender.user_id,       # User A
    token=engine_token,
    expires_at=expires_at,
    active=True
)
    db.session.add(engine_session)

    # ================= ENGINE END ===================

    db.session.commit()

    return jsonify({
        "message": f"Connection request from {sender.username} accepted",
        "engine": "active",
        "expires_at": expires_at.isoformat()
    }), 200
@app.route("/engine/status", methods=["GET"])
@token_required
def engine_status(current_user):

    # Example: engine sessions stored like this
    # engine_sessions = {
    #   user_id: { "expires_at": datetime }
    # }

    session = engine.get(current_user.id)

    if not session:
        return jsonify({
            "engine": "inactive",
            "message": "No active engine session"
        }), 200

    if datetime.utcnow() > session["expires_at"]:
        return jsonify({
            "engine": "expired",
            "expired_at": session["expires_at"]
        }), 200

    return jsonify({
        "engine": "active",
        "connected_as": current_user.username,
        "expires_at": session["expires_at"]
    }), 200
@app.route("/engine/fetch", methods=["POST"])
@token_required
def engine_fetch(current_user):
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    if not is_engine_active(current_user.id):
        return jsonify({"error": "Engine inactive"}), 403

    relay_user_id = current_user.relay_partner_id

    request_id = send_fetch_to_relay(relay_user_id, url)
    if not request_id:
        return jsonify({"error": "Relay offline"}), 503

    response = wait_for_response(request_id)
    return jsonify(response), 200
@app.route("/connection/all", methods=["GET"])
def all_connections():
    connections = Connection.query.all()
    return jsonify([
        {
            "id": c.id,
            "sender_id": c.sender_id,
            "receiver_id": c.receiver_id,
            "status": c.status
        } for c in connections
    ])
@app.route("/connection/decline/<string:sender_id>", methods=["POST"])
@token_required
def decline_request(current_user, sender_id):
    # Find the sender by their unique user_id (e.g. NZPCX, YJ0HI)
    sender = User.query.filter_by(user_id=sender_id).first()

    # Fallback if it's a numeric ID (e.g. 1, 2)
    if not sender:
        try:
            sender = User.query.get(int(sender_id))
        except ValueError:
            sender = None

    if not sender:
        return jsonify({"error": "Sender not found"}), 404

    # Look for the pending connection request
    connection = Connection.query.filter_by(
        sender_id=sender.id,
        receiver_id=current_user.id,
        status="pending"
    ).first()

    if not connection:
        return jsonify({"error": "No pending request found"}), 404

    # Decline the request
    connection.status = "declined"
    db.session.commit()

    return jsonify({
        "message": f"Connection request from {sender.username} declined successfully!"
    }), 200

@app.route("/connection/status", methods=["GET"])
@token_required
def connection_status(current_user):

    # 1. Check if user is connected as SENDER
    sent = Connection.query.filter_by(
        sender_id=current_user.id,
        status="accepted"
    ).first()

    # 2. Check if user is connected as RECEIVER
    received = Connection.query.filter_by(
        receiver_id=current_user.id,
        status="accepted"
    ).first()

    # ✅ If user started request and friend accepted
    if sent:
        friend = User.query.get(sent.receiver_id)

        msg = ""
        if friend.internet_status:
            msg = f"You are now using {friend.username}'s internet via Vicyon."
        else:
            msg = f"{friend.username} is offline (0kbps). Connection lost."

        return jsonify({
            "connected": True,
            "friend": friend.username,
            "friend_id": friend.user_id,
            "online": friend.internet_status,
            "message": msg
        })

    # ✅ If friend requested and user accepted
    if received:
        friend = User.query.get(received.sender_id)

        msg = ""
        if friend.internet_status:
            msg = f"You are now connected with {friend.username} on Vicyon."
        else:
            msg = f"{friend.username} is offline (0kbps). They cannot share internet."

        return jsonify({
            "connected": True,
            "friend": friend.username,
            "friend_id": friend.user_id,
            "online": friend.internet_status,
            "message": msg
        })

    # ✅ Not connected to anyone
    return jsonify({
        "connected": False,
        "message": "Not connected to anyone."
    })
@app.route("/connection/speedtest", methods=["GET"])
@token_required
def speedtest(current_user):
    """Check if device has real internet (0kbps detection)."""
    try:
        # Try connecting to Google DNS (fastest global check)
        socket.create_connection(("8.8.8.8", 53), timeout=2)

        return jsonify({
            "internet": True,
            "message": "Internet active"
        })
    except:
        return jsonify({
            "internet": False,
            "message": "No internet (0kbps)"
        })
    current_user.internet_status = data["internet"]
    db.session.commit()
@app.route("/plans",methods=["GET"])
def list_plans():
    plans = Plan.query.all()
    return jsonify([{"id": p.id, "name": p.name, "price": p.price, "max_receivers": p.max_receivers} for p in plans])
@app.route("/free-trial", methods=["POST"])
def free_trial():
    username = request.json.get("username")
    start_date = datetime.now()
    expiry_date = start_date + timedelta(days=3)
    plans[username] ={"plan": "free-trial", "expiry_date": expiry_date}
    return jsonify({"message": "Free trial activated for 3 days", "expiry_date": expiry_date})
@app.route("/check-expiry", methods=["GET"])
def check_expiry():
    username = request.args.get("username")
    if username not in plans:
       return jsonify({"message": "No active plan."})
    expiry_date = plans[username]["expiry_date"]
    if datetime.now() > expiry_date:
       return jsonify({"status": "expired", "message": "Your plan has expired."})
    else:
        return jsonify({"status": "active", "expiry_date": expiry_date})
@app.route("/use-friend-internet/<int:friend_id>", methods=["POST"])
@token_required
def use_friend_internt(current_user, friend_id):
    friend = User.query.get(friend_id)
    if not friend:
      return jsonify({"error": "Friend not found"}), 404
    active_receivers = Connection.query.filter_by(sender_id=friend.id, status="accepted").count()
    if active_receivers >=friend.plan.max_receivers:
      return jsonify({"error": f"{friend.username}`s {friend.plan.name} plan limit reached"}),403
      return jsonify({"message": f"You are now connected to {friend_id}`s internet via viclink","plan": friend.plan.name,"max_receivers": friend.plan.max_receivers})
@app.route("/config", methods=["GET", "POST"])
@token_required
def config_settings(current_user):
    if request.method == "POST":
      data = request.json
      return jsonify({"message": "Settings saved", "data": data})
    return jsonify({"theme": "blue-white", "notifications": True})
@app.route("/background-sync", methods=["POST"])
def background_sync():
    now = datetime.now()
    expired_users = []
    for user, details in plans.items():
        if now > details["expiry_date"]:
           expired_user.append(user)
    return jsonify({"message": "Background sync complete.", "expired_users": expired_users})
@app.route('/home')
def home():
    if "user_id" not in session:
       return jsonify({"error": "Unauthorized"}), 401
    username = session.get("username")
    return jsonify({"message": f"Welcome {username}!","redirect": "/dashboard"})
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
       return jsonify({"error": "Unauthorized"}), 401
    username = session.get("username")
    return jsonify({"title": "VicLink Dashboard", "message": f"Hello, {username}! You are now in your dashboard."})

@app.route("/session", methods=["GET"])
@jwt_required()
def get_session():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({"logged_in": False, "error": "not logged in"}), 401

    return jsonify({
        "logged_in": True,
        "username": user.username,
        "user_id": user.user_id
    }), 200
@app.route("/Viclink")
def Viclink():
   return jsonify({"message": "welcome to viclink"})
if __name__ == "__main__":
   with app.app_context():
     db.drop_all()
     db.create_all()
     if not Plan.query.first():
       personal = Plan(name="personal",price=400, max_receivers=1)
       friends = Plan(name="Friends", price=700, max_receivers=3)
       db.session.add_all([personal, friends])
       db.session.commit()
       print("plans added succefuly!")
   app.run(debug=True, host="0.0.0.0", port=5000)

