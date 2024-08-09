import http.server
import ssl
import base64
from urllib.parse import urlparse, parse_qs
import os
import configparser
from cryptography.fernet import Fernet, InvalidToken
import logging
from logging.handlers import RotatingFileHandler
from OpenSSL import crypto
import sys
import http.cookies
import secrets
import time
import random
import json
from datetime import datetime, timezone, timedelta
from jinja2 import Environment, FileSystemLoader
import shelve
import dbm
import threading

DEBUG_MODE = os.environ.get("RGB_SCHEDULER_DEBUG_MODE", "false").lower() == "true"
script_dir = os.path.dirname(os.path.abspath(__file__))
secret_path = os.path.join(script_dir, "secret.key")
server_log_path = os.path.join(script_dir, "server.log")
cert_path = os.path.join(script_dir, "cert.pem")
key_path = os.path.join(script_dir, "key.pem")
schedule_file = os.path.join(script_dir, "schedule.json")
sessions_db_path = os.path.join(script_dir, "sessions.db")
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = Environment(loader=FileSystemLoader(template_dir))
config = configparser.ConfigParser()
config.read(os.path.join(script_dir, "config.ini"))


def configure_logging(debug_mode: bool = False) -> logging.Logger:
    """Configure logging with a rotating file handler."""
    logger = logging.getLogger("web_server")

    # Remove all handlers associated with the logger object.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    handler = RotatingFileHandler(
        server_log_path,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
    )
    formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    logger.addHandler(handler)

    return logger


server_logger = configure_logging(debug_mode=DEBUG_MODE)


def clear_old_log_entries(log_file: str, days_to_keep: int = 30) -> None:
    """Clear log entries older than the specified number of days."""
    try:
        now = datetime.now()
        cutoff = now - timedelta(days=days_to_keep)
        lines_kept = []
        lines_cleared = False

        with open(log_file, "r") as file:
            lines = file.readlines()

        with open(log_file, "w") as file:
            for line in lines:
                try:
                    log_time = datetime.strptime(line.split(" ")[0], "%Y-%m-%d")
                    if log_time >= cutoff:
                        lines_kept.append(line)
                    else:
                        lines_cleared = True
                except ValueError:
                    # In case of malformed log entry, just keep it
                    lines_kept.append(line)

            file.writelines(lines_kept)

        if lines_cleared:
            server_logger.info(f"Log entries older than {days_to_keep} days cleared")
    except Exception as e:
        server_logger.error(f"Error clearing old log entries: {e}")


class LoggerWriter:
    """A wrapper for redirecting stdout and stderr to the log file."""

    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != "\n":
            self.logger.log(self.level, message)

    def flush(self):
        pass


sys.stdout = LoggerWriter(server_logger, logging.INFO)
sys.stderr = LoggerWriter(server_logger, logging.ERROR)


def get_key():
    """Get the encryption key from the secret file."""
    try:
        with open(secret_path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        server_logger.error("Encryption key not found")
        raise


def decrypt_password(encrypted_data):
    """Decrypt the password using the encryption key."""
    try:
        key = get_key()
        fernet = Fernet(key)

        # Decode the base64 encoded encrypted data
        encrypted_password = base64.urlsafe_b64decode(encrypted_data)

        # Decrypt the password
        decrypted_password = fernet.decrypt(encrypted_password)
        return decrypted_password.decode()
    except InvalidToken:
        server_logger.error(
            "Invalid token: The encrypted data is not in the correct format"
        )
        return None
    except Exception as e:
        server_logger.error(f"Error decrypting password: {e}")
        return None


try:
    PORT = int(config.get("web.server", "Port"))
    USERNAME = config.get("web.server", "Username")
    encrypted_password = config.get("web.server", "Password")
    PASSWORD = decrypt_password(encrypted_password)
    if PASSWORD is None:
        raise ValueError("Failed to decrypt password")
except Exception as e:
    server_logger.critical(f"Failed to load configuration: {e}")
    raise


def read_schedule():
    """Read the schedule from the schedule file."""
    try:
        with open(schedule_file, "r") as f:
            schedule_data = json.load(f)
        sunrise = (
            datetime.fromisoformat(schedule_data["sunrise"])
            if schedule_data["sunrise"]
            else None
        )
        sunset = (
            datetime.fromisoformat(schedule_data["sunset"])
            if schedule_data["sunset"]
            else None
        )
        last_updated = datetime.fromisoformat(schedule_data["last_updated"])
        return sunrise, sunset, last_updated
    except FileNotFoundError:
        server_logger.error("Schedule file not found")
        return None, None, None, "unknown"
    except json.JSONDecodeError:
        server_logger.error("Error decoding schedule file")
        return None, None, None, "unknown"
    except KeyError as e:
        server_logger.error(f"Missing key in schedule file: {e}")
        return None, None, None, "unknown"


def get_sessions_db():
    """Get the sessions database."""
    try:
        return shelve.open(sessions_db_path, writeback=True)
    except dbm.error as e:
        server_logger.error(f"Failed to open sessions database: {e}")
        # Attempt to recover by creating a new database
        try:
            os.remove(sessions_db_path)
            return shelve.open(sessions_db_path, writeback=True)
        except Exception as recovery_error:
            server_logger.critical(
                f"Failed to recover sessions database: {recovery_error}"
            )
            raise


sessions = get_sessions_db()


class RgbControlHandler(http.server.SimpleHTTPRequestHandler):
    """Handle HTTP requests from the RGB control web page."""

    def log_message(self, format, *args):
        server_logger.info("%s - %s" % (self.address_string(), format % args))

    def do_AUTHHEAD(self):
        """Send the '401 Unauthorized' response header."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="RGB Control"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def create_session(self):
        """Create a new session."""
        session_id = secrets.token_urlsafe(32)
        try:
            sessions[session_id] = {"created_at": time.time(), "last_used": time.time()}
            sessions.sync()
        except Exception as e:
            server_logger.error(f"Failed to create session: {e}")
            return None
        return session_id

    def validate_session(self, session_id):
        """Validate a session."""
        server_logger.debug(f"Attempting to validate session: {session_id}")
        try:
            if session_id in sessions:
                server_logger.debug(f"Session found in database: {session_id}")
                session = sessions[session_id]
                if time.time() - session["created_at"] < 7 * 24 * 60 * 60:  # 7 days
                    session["last_used"] = time.time()
                    sessions.sync()
                    server_logger.debug(f"Session validated and updated: {session_id}")
                    return True
                else:
                    server_logger.info(f"Session expired: {session_id}")
            else:
                server_logger.info(f"Session not found in database: {session_id}")
        except Exception as e:
            server_logger.error(f"Error validating session: {e}", exc_info=True)
        return False

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-type", "image/png")
            self.end_headers()
            isExist = os.path.exists(os.path.join(script_dir, "favicon.png"))
            if isExist:
                with open(os.path.join(script_dir, "favicon.png"), "rb") as f:
                    self.wfile.write(f.read())
            else:
                server_logger.error("Favicon not found")
        else:
            try:
                session_id = None
                if "Cookie" in self.headers:
                    cookie = http.cookies.SimpleCookie(self.headers["Cookie"])
                    if "session" in cookie:
                        session_id = cookie["session"].value
                        server_logger.debug(f"Received session cookie: {session_id}")

                if session_id and self.validate_session(session_id):
                    self.handle_authenticated_request()
                elif self.headers.get("Authorization") is None:
                    self.do_AUTHHEAD()
                    self.wfile.write(b"No auth header received")
                    server_logger.warning(
                        f"Authentication attempt with no header from {self.client_address[0]}"
                    )
                elif (
                    self.headers.get("Authorization")
                    == f'Basic {base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()}'
                ):
                    session_id = self.create_session()
                    if session_id is None:
                        self.send_error(500, "Internal Server Error")
                        return
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")

                    # Set a persistent cookie
                    cookie = http.cookies.SimpleCookie()
                    cookie["session"] = session_id
                    cookie["session"]["httponly"] = True
                    cookie["session"]["secure"] = True
                    cookie["session"]["samesite"] = "Lax"
                    cookie["session"]["path"] = "/"
                    cookie["session"]["expires"] = (
                        datetime.now() + timedelta(days=7)
                    ).strftime("%a, %d %b %Y %H:%M:%S GMT")
                    self.send_header("Set-Cookie", cookie["session"].OutputString())

                    self.end_headers()
                    server_logger.info(
                        f"New persistent session cookie set: {session_id}"
                    )
                    self.handle_authenticated_request()
                else:
                    self.do_AUTHHEAD()
                    self.wfile.write(b"Invalid credentials")
                    server_logger.warning(
                        f"Failed authentication attempt from {self.client_address[0]}"
                    )
            except Exception as e:
                server_logger.error(f"An error occurred during request handling: {e}")
                self.send_error(500, "Internal Server Error")

    def handle_authenticated_request(self):
        """Handle authenticated requests."""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/toggle":
            if "mode" in params:
                mode = params["mode"][0]
                if mode in ["day", "night"]:
                    self.server.set_effect("daytime" if mode == "day" else "nighttime")
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    redirect_script = f"""
                    <html>
                    <head>
                        <title>Redirecting...</title>
                        <style>
                            body {{
                                font-family: 'Arial', sans-serif;
                                background-color: #202020;
                                color: #fff;
                            }}
                        </style>
                        <script>
                            window.location.href = "/?mode={mode}";
                        </script>
                    </head>
                    <body>
                        <p>If you are not redirected, <a href="/?mode={mode}">click here</a></p>
                    </body>
                    </html>
                    """
                    self.wfile.write(redirect_script.encode())

                    server_logger.info(
                        f"Mode changed to {mode.capitalize()} by {self.client_address[0]}"
                    )
                    return
                else:
                    self.send_error(400, "Invalid mode specified")
                    server_logger.warning(
                        f"Invalid mode request from {self.client_address[0]}"
                    )
                    return
            else:
                self.send_error(400, "Mode parameter missing")
                server_logger.warning(
                    f"Missing mode parameter in request from {self.client_address[0]}"
                )
                return

        elif parsed_path.path == "/":
            sunrise, sunset, last_updated = read_schedule()
            now = datetime.now(timezone.utc)

            if sunrise and sunset:
                today_sunrise = sunrise.replace(
                    year=now.year, month=now.month, day=now.day
                )
                today_sunset = sunset.replace(
                    year=now.year, month=now.month, day=now.day
                )

                if DEBUG_MODE:
                    # If sunrise has already passed today, use tomorrow's sunrise
                    if today_sunrise < now:
                        today_sunrise += timedelta(days=1)

                    # Calculate time differences
                    time_to_sunrise = (today_sunrise - now).total_seconds()
                    time_to_sunset = (today_sunset - now).total_seconds()

                    if time_to_sunrise < time_to_sunset:
                        next_event = "sunrise"
                        next_time = today_sunrise
                        current_mode = "night"
                    else:
                        next_event = "sunset"
                        next_time = today_sunset
                        current_mode = "day"
                else:
                    tomorrow_sunrise = today_sunrise + timedelta(days=1)

                    if now < today_sunrise:
                        next_event = "sunrise"
                        next_time = today_sunrise
                        current_mode = "night"
                    elif now < today_sunset:
                        next_event = "sunset"
                        next_time = today_sunset
                        current_mode = "day"
                    else:
                        next_event = "sunrise"
                        next_time = tomorrow_sunrise
                        current_mode = "night"
            else:
                next_event = "Not available"
                next_time = now  # Fallback to current time
                current_mode = "day" if 6 <= now.hour < 18 else "night"

            # Check if mode was passed in the query parameters
            if "mode" in params:
                current_mode = params["mode"][0]

            # Prepare the data for the template
            template_data = {
                "sunrise": sunrise.strftime("%H:%M") if sunrise else "Not available",
                "sunset": sunset.strftime("%H:%M") if sunset else "Not available",
                "last_updated": last_updated.strftime("%Y-%m-%d %H:%M:%S")
                if last_updated
                else "Not available",
                "debug_active": "true" if DEBUG_MODE else "false",
                "next_event": next_event.capitalize(),
                "next_time": next_time.isoformat() if next_time else "",
                "current_mode": current_mode,
            }

            # Render the template
            template = jinja_env.get_template("index.html")
            html_content = template.render(template_data)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(html_content.encode())
            server_logger.info(f"Root path accessed by {self.client_address[0]}")
            return

        self.send_error(404, "Invalid path")


def verify_certificate():
    """Verify the certificate."""
    try:
        with open(cert_path, "r") as cert_file:
            cert_data = cert_file.read()
        cert = ssl.PEM_cert_to_DER_cert(cert_data)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

        server_logger.debug(f"Certificate Subject: {x509.get_subject()}")
        server_logger.debug(f"Certificate Issuer: {x509.get_issuer()}")
        server_logger.debug(f"Certificate Version: {x509.get_version()}")
        server_logger.debug(f"Certificate Serial Number: {x509.get_serial_number()}")
        server_logger.debug(f"Not Before: {x509.get_notBefore()}")
        server_logger.debug(f"Not After: {x509.get_notAfter()}")

        return True
    except Exception as e:
        server_logger.error(f"Certificate verification failed: {e}")
        return False


def run_server(set_effect_func):
    """Run the server."""
    web_server_id = str(random.randint(10000, 99999))
    os.environ["WEB_SERVER_ID"] = web_server_id

    if DEBUG_MODE:
        server_logger.debug("Debug mode activated")

    if not verify_certificate():
        raise Exception("Certificate verification failed")
    try:
        clear_old_log_entries(server_log_path)

        handler = RgbControlHandler
        server_logger.debug(f"Attempting to start server on port {PORT}")
        httpd = http.server.HTTPServer(("", PORT), handler)
        server_logger.debug("HTTP server created successfully")
        httpd.set_effect = set_effect_func

        server_logger.debug("Attempting to create SSL context")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        context.options |= (
            ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 and 1.1
            | ssl.OP_NO_COMPRESSION  # Disable TLS compression
            | ssl.OP_CIPHER_SERVER_PREFERENCE  # Use server's cipher ordering preference
            | ssl.OP_SINGLE_DH_USE  # Improve forward secrecy
            | ssl.OP_SINGLE_ECDH_USE  # Improve forward secrecy
        )
        context.set_ciphers(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
        )

        server_logger.debug(
            f"Loading certificate from {cert_path} and key from {key_path}"
        )
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server_logger.debug("SSL context created and certificate loaded successfully")

        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        server_logger.debug("Socket wrapped with SSL successfully")

        server_logger.info(
            f"Server started successfully on port {PORT}, WEB_SERVER_ID: {web_server_id}"
        )

        def cleanup_sessions():
            """Clean up expired sessions."""
            try:
                current_time = time.time()
                for session_id in list(sessions.keys()):
                    if (
                        current_time - sessions[session_id]["created_at"]
                        >= 7 * 24 * 60 * 60
                    ):
                        del sessions[session_id]
                sessions.sync()
            except Exception as e:
                server_logger.error(f"Error during session cleanup: {e}")

        # Run cleanup every hour

        cleanup_thread = threading.Thread(
            target=lambda: (
                cleanup_sessions(),
                threading.Timer(3600, cleanup_sessions).start(),
            )
        )
        cleanup_thread.daemon = True
        cleanup_thread.start()

        httpd.serve_forever()
    except Exception as e:
        server_logger.critical(f"Server failed to start: {e}", exc_info=True)
        raise
    finally:
        try:
            sessions.close()
        except Exception as e:
            server_logger.error(f"Error closing sessions database: {e}")


if __name__ == "__main__":
    try:
        run_server()
    except Exception as e:
        server_logger.critical(f"Unhandled exception in main: {e}")
        sys.exit(1)
