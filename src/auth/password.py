import hashlib
import bcrypt

# Current password hashing configuration
ALGORITHM = 'bcrypt'
ROUNDS = 12
MEMORY_COST = 32768

def hash_password(password):
    """Hash a password using the current algorithm"""
    if ALGORITHM == 'bcrypt':
        salt = bcrypt.gensalt(rounds=ROUNDS)
        return bcrypt.hashpw(password.encode(), salt)
    elif ALGORITHM == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {ALGORITHM}")

def verify_password(password, hashed):
    """Verify a password against its hash"""
    if ALGORITHM == 'bcrypt':
        return bcrypt.checkpw(password.encode(), hashed.encode())
    elif ALGORITHM == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest() == hashed
    else:
        raise ValueError(f"Unsupported algorithm: {ALGORITHM}")