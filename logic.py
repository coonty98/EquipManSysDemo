import re
from flask import session, redirect, url_for, abort
from functools import wraps

def read_secret(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return None

def is_valid_password(password):
    # Minimum 8 characters, at least one uppercase, one lowercase, one digit, one special character
    if len(password) < 8:
        # return False, "Password must be at least 8 characters long."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"[A-Z]", password):
        # return False, "Password must contain at least one uppercase letter."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"[a-z]", password):
        # return False, "Password must contain at least one lowercase letter."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"\d", password):
        # return False, "Password must contain at least one digit."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        # return False, "Password must contain at least one special character."
        return False, "Password does not meet requirements. Try again."
    return True, ""

def get_user_labs():
    return session.get('labs', [])
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_access_levels(*levels):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user's access level is in allowed levels
            if session.get('access_level') in levels:
                return f(*args, **kwargs)
            abort(403)
        return decorated_function
    return decorator