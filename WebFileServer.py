# 20.01.2025
# A web file server with login screen
# requirments: pip install -r requirements.txt

from flask import Flask, request, render_template, redirect, url_for, send_file, session
import os
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import argparse
from KeyGen import KeyGen as kg
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

PORT = 4433  # HTTPS port
CERT_FILE = "certs/cert.pem"
KEY_FILE = "certs/key.pem"

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for session handling
app.wsgi_app = ProxyFix(app.wsgi_app)

# Add these settings after app initialization
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)  # Sessions expire after 30 minutes
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Add security headers including HSTS
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Add these at the top with your other imports
failed_attempts = {}
MAX_ATTEMPTS = 2
LOCKOUT_TIME = 5  # minutes

# Add this function to check for lockouts
def check_lockout(ip):
    if ip in failed_attempts:
        attempts, lockout_time = failed_attempts[ip]
        if attempts >= MAX_ATTEMPTS:
            if datetime.now() < lockout_time:
                time_left = (lockout_time - datetime.now()).seconds // 60
                print ("Lockout user: ", ip)
                return f"Too many failed attempts. Please wait {time_left} minutes."
            else:
                failed_attempts.pop(ip)
    return None

def validate_public_key(key_data):
    """Validate that the uploaded file is a valid PEM public key"""
    try:
        # Check if content starts and ends with proper PEM markers
        if not key_data.startswith(b'-----BEGIN PUBLIC KEY-----') or \
           not key_data.endswith(b'-----END PUBLIC KEY-----\n'):
            return False
            
        # Try to load the key to verify its format
        load_pem_public_key(key_data, backend=default_backend())
        return True
    except Exception as e:
        print(f"[X] Key validation error: {str(e)}")
        return False

def failed_login(ip:int):
    # Handle failed login attempt
    if ip in failed_attempts:
        attempts, lockout_time = failed_attempts[ip]
        failed_attempts[ip] = (attempts + 1, datetime.now() + timedelta(minutes=LOCKOUT_TIME) if attempts + 1 >= MAX_ATTEMPTS else lockout_time)
    else:
        failed_attempts[ip] = (1, datetime.now() + timedelta(minutes=LOCKOUT_TIME))
    
    attempts_left = MAX_ATTEMPTS - failed_attempts[ip][0]
    error_msg = f"Invalid public key. {attempts_left} attempts remaining before lockout."
    print(f"[X] Failed login attempt from {ip}. \n{attempts_left} attempts remaining.")
    return error_msg

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        
        # Check if user is locked out
        lockout_msg = check_lockout(ip)
        if lockout_msg:
            return render_template('login.html', error=lockout_msg, is_locked=True)
            
        # Check for the public key file in the request
        if 'public_key' not in request.files:
            return render_template('login.html', error="Please upload your public key", is_locked=False)
        file = request.files['public_key']
        if file.filename == "":
            return render_template('login.html', error="No file selected", is_locked=False)
        
        # Validate file extension
        if not file.filename.endswith('.pem'):
            failed_login(ip)
            print("[X] Invalid file type")
            return render_template('login.html', error="Invalid file type. Please upload a .pem file", is_locked=False)
        
        # Read uploaded public key content
        uploaded_key_data = file.read()

        # Check file size (prevent large file uploads)
        if len(uploaded_key_data) > 3000:  # Maximum 3KB
            failed_login(ip)
            print("[X] Key file too large")
            return render_template('login.html', error="Key file too large", is_locked=False)
        
        # Validate key format
        if not validate_public_key(uploaded_key_data):
            failed_login(ip)
            print("[X] Invalid public key format")
            return render_template('login.html', error="Invalid public key format", is_locked=False)

        # Load stored public key from file
        try:
            with open("public_key.pem", "rb") as f:
                stored_key_data = f.read()
        except Exception as e:
            print("[X] Error loading stored public key:", e)
            return render_template('login.html', error="Server error: unable to load public key", is_locked=False)
        
        # Compare the uploaded key with the stored key
        if uploaded_key_data == stored_key_data:
            # Reset failed attempts on successful login
            if ip in failed_attempts:
                failed_attempts.pop(ip)
            session['logged_in'] = True
            return redirect(url_for('file_server'))
        else:
            error_msg = failed_login(ip)
            return render_template('login.html', error=error_msg, is_locked=False)

    return render_template('login.html', error=None, is_locked=False)

@app.route('/files')
@login_required
def file_server():
    files = os.listdir('files')
    return render_template('files.html', files=files)

@app.route('/files/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join('files', filename)
    # Add path traversal protection
    if not os.path.abspath(file_path).startswith(os.path.abspath('files')):
        return "Access denied", 403
    if not os.path.exists(file_path):
        return "File not found", 404
    return send_file(file_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

def parse_arguments():
    parser = argparse.ArgumentParser(description='Web File Server with configurable running time')
    parser.add_argument('-r','--runtime', type=int, default=0, help='Server running time in hours (default = unlimited')
    parser.add_argument('-k', '--key', action='store_true',help='Generate new RSA pair of keys')
    parser.add_argument('-c', '--certificate', action='store_true',help='Generate new SSL certificate, need to have OpenSSL installed')
    parser.add_argument('-v', '--validate', action='store_true',help='RSA key validation')
    return parser.parse_args()

def CheckKey():
    private_key = kg.load_key_from_file("private_key.pem", is_private=True)
    if private_key is None:
        print("[X] Exiting due to missing private key\n[*] generating new keys.")
        return False
    public_key = kg.load_key_from_file("public_key.pem")
    if public_key is None:
        print("[X] Exiting due to missing public key\n[*] generating new keys.")
        return False
    return True

def ValidateKey():
    private_key = kg.load_key_from_file("private_key.pem", is_private=True)
    public_key = kg.load_key_from_file("public_key.pem")
    if private_key and public_key: # Check if keys loaded successfully
        data = b"[V] This is the data to be signed"
        signature = kg.sign_api_request(private_key, data)
        # print("Signature:", signature)
        is_valid = kg.verify_api_request(public_key, data, signature)
    return is_valid

def generate_certificates():
    """Generate SSL certificates using OpenSSL"""
    if not os.path.exists('certs'):
        os.makedirs('certs')
    print("[*] Generating new SSL certificates...")
    try:
        import subprocess
        if not os.path.exists('certs'):
            os.makedirs('certs')
        # Generate private key and self-signed certificate
        subprocess.run([
            'openssl', 'req', '-x509', 
            '-newkey', 'rsa:4096', 
            '-nodes',
            '-out', "certs\\"+CERT_FILE,
            '-keyout', "certs\\"+KEY_FILE,
            '-days', '365',
            '-subj', '/CN=localhost'
        ], check=True)
        print("[V] Certificates generated successfully")
        return True
    except Exception as e:
        print(f"[X] Error generating certificates: {str(e)}\nMake use you have installed OpenSSL")
        return False

if __name__ == '__main__':
    print ("-- Debby's Web File Server --")
    args = parse_arguments()
    
    if args.key:
        kg.generate_rsa_key_pair()
        print("[*] New RSA key pair generated")
    
    if args.certificate:
        generate_certificates()
        print("[*] New SSL certificates generated")

    if not os.path.exists('files'):
        os.makedirs('files')
    if not os.path.exists('certs'):
        os.makedirs('certs')
        print("[X] Please generate SSL certificates in the 'certs' directory")
        exit(1)
    
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("[X] SSL certificates not found in 'certs' directory\nPlease generate them first")
        exit(1)
    if not CheckKey():
        print("[X] Error loading keys, please generate new keys")
        exit(1)
        
    if args.validate:
        if ValidateKey():
            # Process the API request
            print("[V] RSA keys are valid")
        else:
            print("[X] RSA keys are not valid")
        exit(1)
    
    start_time = datetime.now()
    if args.runtime > 0:
        end_time = start_time + timedelta(hours=args.runtime)
        print(f"[*] Server will run for {args.runtime} hours")
        print(f"[*] Start time: {start_time.strftime('%H:%M:%S')}")
        print(f"[*] End time: {end_time.strftime('%H:%M:%S')}")
    else:
        print("[*] Server will run indefinitely")
        print(f"[*] Start time: {start_time.strftime('%H:%M:%S')}")

    def flask_runner():
        app.run(
            host='0.0.0.0',
            port=PORT,
            ssl_context=(CERT_FILE, KEY_FILE),
            debug=False
        )

    if args.runtime > 0:
        import threading
        import time

        def shutdown_timer():
            while datetime.now() < end_time:
                time.sleep(60)  # Check every minute
            print("\n[*] Server runtime expired. Shutting down...")
            os._exit(0)

        timer_thread = threading.Thread(target=shutdown_timer, daemon=True)
        timer_thread.start()

    flask_runner()