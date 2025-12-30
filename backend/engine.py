# engine.py
from datetime import datetime, timedelta

# In-memory engine sessions
engine = {}

def start_engine(user_id, minutes=30):
    """
    Start engine session for a user
    """
    expires_at = datetime.utcnow() + timedelta(minutes=minutes)
    engine[user_id] = {
        "expires_at": expires_at
    }
    return engine[user_id]

def get_engine(user_id):
    """
    Get engine session
    """
    return engine.get(user_id)

def is_engine_active(user_id):
    """
    Check if engine session is active
    """
    session = engine.get(user_id)
    if not session:
        return False
    return datetime.utcnow() < session["expires_at"]
