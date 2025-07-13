import hashlib
import secrets
import time
import json
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import request, session, flash, redirect, url_for
import logging
import bleach

# Configure security logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/security.log'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

class SecurityManager:
    """Centralized security management"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = {}
        self.max_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
        self.block_duration = 1800  # 30 minutes
        
    def record_failed_login(self, ip_address, username):
        """Record failed login attempt"""
        current_time = time.time()
        
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []
        
        self.failed_attempts[ip_address].append({
            'timestamp': current_time,
            'username': username
        })
        
        # Remove attempts older than 1 hour
        self.failed_attempts[ip_address] = [
            attempt for attempt in self.failed_attempts[ip_address]
            if current_time - attempt['timestamp'] < 3600
        ]
        
        # Block IP if too many attempts
        if len(self.failed_attempts[ip_address]) >= self.max_attempts:
            self.blocked_ips[ip_address] = current_time + self.block_duration
            security_logger.warning(f"IP {ip_address} blocked for {self.max_attempts} failed login attempts")
        
        security_logger.warning(f"Failed login attempt from {ip_address} for username {username}")
    
    def is_ip_blocked(self, ip_address):
        """Check if IP is currently blocked"""
        if ip_address in self.blocked_ips:
            if time.time() < self.blocked_ips[ip_address]:
                return True
            else:
                # Unblock expired IPs
                del self.blocked_ips[ip_address]
        return False
    
    def clear_failed_attempts(self, ip_address):
        """Clear failed attempts for successful login"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def get_failed_attempt_count(self, ip_address):
        """Get number of failed attempts for IP"""
        return len(self.failed_attempts.get(ip_address, []))

class PasswordManager:
    """Secure password handling"""
    
    @staticmethod
    def hash_password(password):
        """Hash password securely"""
        return generate_password_hash(password, method='pbkdf2:sha256', salt_length=32)
    
    @staticmethod
    def verify_password(password_hash, password):
        """Verify password against hash"""
        return check_password_hash(password_hash, password)
    
    @staticmethod
    def generate_secure_password(length=16):
        """Generate cryptographically secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def is_password_strong(password):
        """Check if password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "Password must contain uppercase, lowercase, number, and special character"
        
        return True, "Password is strong"

class FileSecurityManager:
    """Secure file upload handling"""
    
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    ALLOWED_MIME_TYPES = {
        'image/png', 'image/jpeg', 'image/jpg', 
        'image/gif', 'image/webp'
    }
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    @staticmethod
    def is_allowed_file(filename):
        """Check if file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in FileSecurityManager.ALLOWED_EXTENSIONS
    
    # Note: Advanced MIME type validation would use python-magic
    # but we're using extension-based validation for Windows compatibility
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to prevent path traversal"""
        filename = os.path.basename(filename)
        filename = ''.join(c for c in filename if c.isalnum() or c in '._-')
        if len(filename) > 100:
            name, ext = os.path.splitext(filename)
            filename = name[:95] + ext
        return filename
    
    @staticmethod
    def generate_secure_filename(original_filename):
        """Generate secure unique filename"""
        ext = os.path.splitext(original_filename)[1].lower()
        secure_name = secrets.token_hex(16) + ext
        return secure_name

class InputSanitizer:
    """Input sanitization and validation"""
    
    @staticmethod
    def sanitize_html(text):
        """Remove dangerous HTML tags and attributes"""
        allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li']
        return bleach.clean(text, tags=allowed_tags, strip=True)
    
    @staticmethod
    def sanitize_string(text, max_length=None):
        """Sanitize string input"""
        if not isinstance(text, str):
            return ""
        
        # Remove dangerous characters
        text = text.strip()
        text = ''.join(c for c in text if ord(c) < 127)  # ASCII only
        
        if max_length:
            text = text[:max_length]
        
        return text
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

class SessionManager:
    """Secure session management"""
    
    @staticmethod
    def create_secure_session(username, user_role):
        """Create secure session"""
        session['user_logged_in'] = True
        session['username'] = username
        session['user_role'] = user_role
        session['login_time'] = datetime.now().timestamp()
        session['last_activity'] = datetime.now().timestamp()
        session['session_token'] = secrets.token_hex(32)
        
        security_logger.info(f"Secure session created for user: {username}")
    
    @staticmethod
    def validate_session():
        """Validate current session"""
        if not session.get('user_logged_in'):
            return False
        
        # Check session timeout
        last_activity = session.get('last_activity')
        if not last_activity:
            return False
        
        timeout = int(os.getenv('SESSION_TIMEOUT', 1800))
        if time.time() - last_activity > timeout:
            SessionManager.destroy_session()
            return False
        
        # Update last activity
        session['last_activity'] = time.time()
        return True
    
    @staticmethod
    def destroy_session():
        """Safely destroy session"""
        username = session.get('username', 'unknown')
        session.clear()
        security_logger.info(f"Session destroyed for user: {username}")
    
    @staticmethod
    def require_auth(required_role=None):
        """Decorator for authentication required routes"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not SessionManager.validate_session():
                    flash('Please log in to access this area.', 'error')
                    return redirect(url_for('admin_login'))
                
                if required_role and session.get('user_role') != required_role:
                    flash('Insufficient permissions.', 'error')
                    return redirect(url_for('admin_dashboard'))
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator

# Global security manager instance
security_manager = SecurityManager()

def log_security_event(event_type, details, ip_address=None):
    """Log security events"""
    if not ip_address:
        ip_address = request.remote_addr if request else 'unknown'
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'details': details,
        'ip_address': ip_address,
        'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'unknown'
    }
    
    security_logger.info(f"Security Event: {event_type} - {details} from {ip_address}")
    
    # Also save to JSON log file
    log_file = 'logs/security_events.json'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            events = json.load(f)
    else:
        events = []
    
    events.append(log_entry)
    
    # Keep only last 1000 events
    events = events[-1000:]
    
    with open(log_file, 'w') as f:
        json.dump(events, f, indent=2) 