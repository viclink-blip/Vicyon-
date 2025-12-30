from flask import Flask, request, jsonify
from functools import wraps
import jwt
import datetime
from werkzeug.security import generate_password_hash,check_password_hash
app = Flask(__name__) 
app.config['SECRET_KEY'] = "YOUR_SECRET_KEY" # Change this in production

# Temporary in-memory storage
users = {} # {username: password_hash} 
connection_requests = {} # {receiver: [requesters]} 
connections = [] # [(user1, user2)]

# JWT Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args,  **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'error': 'Token is  missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user =  data['username']
        except:
            return jsonify({'error': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Home route
@app.route("/")
def home():
     return "Hello, VicLink is running!"

# Status route
@app.route("/viclink")
def viclink_info():
    return jsonify({"status": "VicLink is live", "message": "Welcome!", "version": "1.0"})

# Register a new user
@app.route("/register", methods=["POST"])
def register(): 
    data = request.json
    username = data.get("username") 
    password = data.get("password")
    if not username or  not password:
        return jsonify({"error": "Username and password are required"}), 400
    if username in users:
       return jsonify({"error": "Username already exists"}), 409
    password_hash = generate_password_hash(password) 
    users[username] = password_hash
    return jsonify({"message": f"User '{username}' registered successfully!"}), 201

# Login a user
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username") 
    password = data.get("password")
    if username not in  users or not check_password_hash(users[username], password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = jwt.encode({ "username": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({"message": f"Welcome {username}!", "token": token})

# Send connection request
@app.route("/request_connection", methods=["POST"]) 
@token_required
def request_connection(current_user):
    data = request.json
    friend = data.get("friend")
    if friend not in users:
        return jsonify({"error": "Friend user not found"}), 404
    if friend not in connection_requests: 
        connection_requests[friend] = []
    if current_user in connection_requests[friend] or (current_user, friend) in connections:
        return jsonify({"error": "Request already sent or already connected"}), 400
    connection_requests[friend].append(current_user) 
    return jsonify({"message": f"Connection request sent to {friend}."})

# Approve or reject connection request
@app.route("/respond_connection", methods=["POST"]) 
@token_required
def respond_connection(current_user):
    data = request.json
    requester = data.get("requester") 
    accept = data.get("accept", False)
    if current_user  not in connection_requests or requester not in connection_requests[current_user]:
        return jsonify({"error": "No such connection request"}), 404
    connection_requests[current_user].remove(requester) 
    if accept:
        connections.append((current_user, requester)) 
        return jsonify({"message": f"You are now connected with {requester}!"})
    return jsonify({"message": f"You rejected the connection request from {requester}."})

# Simulate using friend's internet
@app.route("/use_friend_internet", methods=["POST"]) 
@token_required
def use_friend_internet(current_user):
    data = request.json
    friend = data.get("friend")
    if  (current_user, friend) not in connections and (friend, current_user) not in connections:
        return jsonify({"error": "You are not connected with this friend"}), 403
    return jsonify({"message": f"You are now remotely using {friend}'s internet via VicLink!"})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
