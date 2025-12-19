#!/usr/bin/env python3
"""
vulnerable_app.py

Dummy Python application intentionally containing many insecure coding patterns
for SAST scanner testing. Contains hardcoded secrets, SQL injection, command
injection, unsafe deserialization, use of eval/exec, weak crypto, insecure TLS,
insecure file handling, and more.

WARNING: For testing only. Run in a safe, isolated environment.
"""

import os
import sys
import subprocess
import sqlite3
import tempfile
import hashlib
import random
import secrets
import pickle
import yaml
import json
import base64
import urllib.request
import ssl
import smtplib
from http.server import BaseHTTPRequestHandler, HTTPServer

############################################
# Section: Hardcoded secrets & credentials
############################################

# Hardcoded API keys and credentials (vulnerability: secrets in source)
DB_PASSWORD = "P@ssw0rd1234"  # hardcoded password
AWS_ACCESS_KEY = "AKIAEXAMPLEACCESS"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENCRYPTION_KEY = b"this_is_a_very_bad_key_123"  # static symmetric key

# Hardcoded SMTP creds
SMTP_USER = "admin@example.com"
SMTP_PASS = "emailPa$$"

# Configuration as a JSON string with creds embedded
CONFIG_JSON = '{"db_user":"root","db_pass":"%s","api_token":"sometoken"}' % DB_PASSWORD

############################################
# Section: Insecure crypto & randomness
############################################

def weak_hash_password(password: str) -> str:
    # MD5 is considered weak for password hashing
    m = hashlib.md5()
    m.update(password.encode('utf-8'))
    return m.hexdigest()

def insecure_token():
    # Using random.random and base64 — predictable token
    r = random.random()
    token = base64.b64encode(str(r).encode()).decode()
    return token

def insecure_secret_generation():
    # Using a hardcoded key and base64 makes tokens predictable
    payload = b"user:admin"
    token = base64.b64encode(payload + ENCRYPTION_KEY[:8])
    return token.decode()

############################################
# Section: SQL Injection (sqlite example)
############################################

DB_PATH = "vulndb.sqlite"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);")
    # Insert dummy user
    cur.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'alice', 'alicepass');")
    conn.commit()
    conn.close()

def bad_sql_query(username):
    # Vulnerable: direct string formatting with user input -> SQL injection
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = "SELECT id, username FROM users WHERE username = '%s';" % username
    print("Executing query:", query)
    cur.execute(query)
    result = cur.fetchall()
    conn.close()
    return result

def good_sql_query(username):
    # Safer parameterized example (left for contrast)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE username = ?;", (username,))
    result = cur.fetchall()
    conn.close()
    return result

############################################
# Section: Command injection / shell=True
############################################

def list_files_unsafe(dir_name):
    # Dangerous: building shell command with user input and shell=True
    cmd = "ls -la %s" % dir_name
    print("Running (unsafe):", cmd)
    output = subprocess.check_output(cmd, shell=True)  # shell injection risk
    return output.decode()

def run_user_command(cmd):
    # dangerously executes arbitrary user-provided command via eval of string
    # (demonstrates unsafe eval usage)
    # NOTE: In real life, never eval user commands
    print("About to eval:", cmd)
    return eval(cmd)  # extremely dangerous

############################################
# Section: Unsafe deserialization
############################################

def deserialize_with_pickle(data_bytes):
    # Unsafe: untrusted pickle deserialization
    obj = pickle.loads(data_bytes)
    return obj

def safe_deserialize_json(s):
    # safer example
    return json.loads(s)

############################################
# Section: YAML unsafe_load
############################################

def load_yaml_unsafe(yaml_str):
    # yaml.unsafe_load (or yaml.load without specifying Loader) can execute arbitrary objects
    return yaml.unsafe_load(yaml_str)

############################################
# Section: Insecure HTTP / SSL verification disabled
############################################

def fetch_url_insecure(url):
    # Disables SSL verification (requests-like insecure behavior using urllib)
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(url, context=context) as resp:
        return resp.read().decode()

############################################
# Section: Web server that evals inputs (vulnerable demo)
############################################

class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Extract a query-param-like value (super-simplified)
        # This server intentionally uses eval() on user-supplied data.
        try:
            # naive parsing: ?q=...
            q = None
            if '?' in self.path:
                q = self.path.split('?', 1)[1]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            if q:
                # user-controlled string gets eval'd
                result = eval(q)  # vulnerability
                self.wfile.write(("Result: %s\n" % repr(result)).encode())
            else:
                self.wfile.write(b"Hello from vulnerable server\n")
        except Exception as e:
            self.wfile.write(("Error: %s\n" % e).encode())

def start_vulnerable_server(port=8000):
    server = HTTPServer(('127.0.0.1', port), VulnerableHandler)
    print("Starting vulnerable server on http://127.0.0.1:%d" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

############################################
# Section: Insecure file handling & world-writable permissions
############################################

def create_insecure_temp_file(data):
    # Insecure usage of tempfile.NamedTemporaryFile on Windows or manual mode with open()
    temp_dir = tempfile.gettempdir()
    path = os.path.join(temp_dir, "vuln_temp.txt")
    # Open with default mode (may be world-readable) and set 777 perms
    with open(path, "w") as f:
        f.write(data)
    # Make file world-writable/readable (insecure)
    try:
        os.chmod(path, 0o777)
    except Exception:
        # May fail on Windows; ignore
        pass
    return path

############################################
# Section: Insecure email sending with plaintext creds
############################################

def send_insecure_email(to_addr, subject, body):
    # Sends email with hardcoded credentials and no TLS usage demonstration (vulnerable)
    server = smtplib.SMTP("smtp.example.com", 25)
    msg = f"From: {SMTP_USER}\nTo: {to_addr}\nSubject: {subject}\n\n{body}"
    server.login(SMTP_USER, SMTP_PASS)  # plaintext creds in code
    server.sendmail(SMTP_USER, [to_addr], msg)
    server.quit()

############################################
# Section: Unsafe use of pickle over network (simulated)
############################################

def receive_and_deserialize_simulated(raw_data):
    # Pretend raw_data was received from network and directly unpickle
    return deserialize_with_pickle(raw_data)

############################################
# Section: Using insecure random for tokens
############################################

def token_with_random_module():
    # Using random instead of secrets
    t = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    return t

def token_with_secrets_good():
    # Proper way for comparison
    return secrets.token_hex(16)

############################################
# Section: Insecure use of eval/exec in helpers
############################################

def execute_user_code(user_code):
    # Demonstrates exec on dynamic code
    local_scope = {}
    exec(user_code, {}, local_scope)
    return local_scope

############################################
# Section: Insecure config parsing from env + eval
############################################

def load_config_from_env():
    # Reads config from environment variable and evals it (dangerous)
    s = os.environ.get("VULN_CONFIG", "{'mode':'safe'}")
    cfg = eval(s)  # vulnerability
    return cfg

############################################
# Section: Hardcoded JWT-like token parsing (insecure)
############################################
def parse_jwt_naive(jwt_str):
    # naive parsing and ignoring signature/alg checks
    try:
        header_b64, payload_b64, sig = jwt_str.split('.')
        payload = base64.b64decode(payload_b64 + "==").decode()
        return json.loads(payload)
    except Exception as e:
        return {"error": str(e)}

############################################
# Section: Insecure temporary credentials file
############################################

def write_aws_creds():
    # Writes AWS creds to a file with broad permissions and no encryption
    home = os.path.expanduser("~")
    creds_file = os.path.join(home, ".aws", "credentials_vuln")
    os.makedirs(os.path.dirname(creds_file), exist_ok=True)
    with open(creds_file, "w") as f:
        f.write(f"[default]\naws_access_key_id = {AWS_ACCESS_KEY}\naws_secret_access_key = {AWS_SECRET_KEY}\n")
    try:
        os.chmod(creds_file, 0o666)
    except Exception:
        pass
    return creds_file

############################################
# Section: Insecure use of eval on configuration file
############################################

def read_and_eval_config_file(path):
    # Reads a config file and evals it, assuming python literal
    with open(path, "r") as f:
        data = f.read()
    return eval(data)  # vulnerability

############################################
# Section: Unsafe XML / XXE-like placeholder (simulated)
############################################

def parse_xml_unsafe(xml_str):
    # This is a placeholder to indicate insecure XML parsing (XXE risk)
    # (we won't import lxml to avoid complexity). We'll just show a "dangerous" path.
    if "<!ENTITY" in xml_str:
        # pretend it resolved external entity
        return "external entity resolved (simulated)"
    return "ok"

############################################
# Section: Simulated insecure deserialization via jsonpickle (concept)
############################################

def unsafe_jsonpickle_like(s):
    # Simulate the pattern where a library reconstitutes objects unsafely
    # e.g., jsonpickle.loads(s)
    # We'll just call eval to emulate unsafe behavior
    return eval(s)

############################################
# Section: Misuse of file system permissions and symlinks
############################################
def overwrite_important_file(target_path):
    # Demonstrates writing to arbitrary path without validation
    with open(target_path, "w") as f:
        f.write("OVERWRITTEN_BY_VULN_APP")
    try:
        os.chmod(target_path, 0o666)
    except Exception:
        pass

############################################
# Section: Main CLI that accepts arguments unsafely
############################################

def main_cli():
    if len(sys.argv) < 2:
        print("Usage: python vulnerable_app.py <action> [args]")
        print("Actions: initdb, query, token, server, temp, exec, email, writecreds")
        return

    action = sys.argv[1]

    if action == "initdb":
        init_db()
        print("DB initialized.")

    elif action == "query":
        # second argument is username; we call bad_sql_query directly
        if len(sys.argv) < 3:
            print("Usage: query <username>")
            return
        username = sys.argv[2]
        res = bad_sql_query(username)
        print("Query result:", res)

    elif action == "token":
        print("Weak token:", insecure_token())
        print("Better token:", token_with_secrets_good())

    elif action == "server":
        # start the vulnerable server (blocking)
        start_vulnerable_server(port=8000)

    elif action == "temp":
        path = create_insecure_temp_file("sensitive data here")
        print("Wrote insecure temp file to", path)

    elif action == "exec":
        if len(sys.argv) < 3:
            print("Usage: exec <python_expression>")
            return
        expr = sys.argv[2]
        print("Eval result:", run_user_command(expr))

    elif action == "email":
        if len(sys.argv) < 3:
            print("Usage: email <to>")
            return
        to = sys.argv[2]
        send_insecure_email(to, "Test Subject", "This is a test body")

    elif action == "writecreds":
        path = write_aws_creds()
        print("Wrote AWS creds to", path)

    else:
        print("Unknown action:", action)

############################################
# Section: Some dummy library-like functions with insecure defaults
############################################

def library_function_accepting_user_json(s):
    # Accepts user data and uses eval on a decoded component (dangerous)
    data = json.loads(s)
    if "calc" in data:
        # Evaluate expression from JSON payload
        return eval(data["calc"])  # dangerous
    return data

def load_plugin_unchecked(plugin_code):
    # Loads plugin code via exec without sandboxing
    ns = {}
    exec(plugin_code, ns)  # insecure plugin loading
    return ns

############################################
# Section: Simulated insecure mobile/web token handling
############################################

SESSION_STORE = {}

def login_user(username, password):
    # Bad: stores plaintext password and returns weak token
    SESSION_STORE[username] = {"password": password}
    return insecure_token()

def authenticate_request(username, token):
    # Checks token in a very naive way
    s = SESSION_STORE.get(username)
    if not s:
        return False
    return token.startswith("AA")  # obviously wrong

############################################
# Section: Unsafe use of subprocess to download files
############################################

def download_file_unsafe(url, dest):
    # Uses wget via shell, exposing to shell injection if url is attacker-controlled
    cmd = f"wget -O {dest} {url}"
    subprocess.call(cmd, shell=True)
    return dest

############################################
# Section: Misc insecure patterns (comments-only examples)
############################################
# - using eval on config file values
# - ignoring SSL certificate validation
# - sending credentials via query parameters over HTTP
# - storing secrets in environment variables but committing them to VCS
# - using weak ciphers / outdated libraries (not executed here)

############################################
# Run main if executed directly
############################################
if __name__ == "__main__":
    # Populate DB for demo
    init_db()

    # Example usages to generate SAST findings during static analysis:
    # - Hardcoded secrets: AWS_ACCESS_KEY, AWS_SECRET_KEY, DB_PASSWORD
    # - MD5 usage in weak_hash_password
    # - random instead of secrets in token_with_random_module/insecure_token
    # - SQL injection in bad_sql_query
    # - use of shell=True in list_files_unsafe / download_file_unsafe
    # - eval/exec in run_user_command, execute_user_code, load_config_from_env, etc.
    # - pickle.loads in deserialize_with_pickle
    # - yaml.unsafe_load in load_yaml_unsafe
    # - SSL verification disabled in fetch_url_insecure
    # - insecure file permissions via os.chmod(0o777/0o666)
    #
    # The script intentionally does not call network or destructive operations automatically,
    # but exposes functions / CLI commands to exercise these patterns.

    # If user provided args, run CLI; otherwise print short summary
    if len(sys.argv) > 1:
        main_cli()
    else:
        print("vulnerable_app.py ready. Run with: python vulnerable_app.py <action>")
        print("Examples: python vulnerable_app.py query \"' OR '1'='1\"")
        print("          python vulnerable_app.py exec \"__import__('os').listdir('.')\"")
