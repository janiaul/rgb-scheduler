import http.server
import ssl
import base64
from urllib.parse import urlparse, parse_qs
import os
import sys
import http.cookies
import secrets
import time
import random
import json
from datetime import datetime, timezone, timedelta
import threading

from cryptography.fernet import Fernet, InvalidToken
import logging
from rgb_scheduler.logging_utils import configure_logging, clear_old_log_entries
from rgb_scheduler.config_utils import (
    load_config,
    get_signalrgb_info,
    get_philips_hue_info,
)
from rgb_scheduler.hue_utils import toggle_hue, set_manual_hue_scene
from OpenSSL import crypto
from jinja2 import Environment, FileSystemLoader
import shelve
import dbm

from rgb_scheduler.path_utils import (
    get_log_path,
    get_data_path,
    get_config_path,
    get_template_path,
    get_static_path,
)

# --- Path and env setup ---
DEBUG_MODE = os.environ.get("RGB_SCHEDULER_DEBUG_MODE", "false").lower() == "true"

secret_path = get_data_path("secret.key")
server_log_path = get_log_path("server.log")
cert_path = get_data_path("cert.pem")
key_path = get_data_path("key.pem")
schedule_file = get_data_path("schedule.json")
effects_file = get_data_path("effects.json")
scenes_file = get_data_path("scenes.json")
sessions_db_path = get_data_path("sessions.db")
template_dir = get_template_path()
jinja_env = Environment(loader=FileSystemLoader(template_dir))

server_logger = configure_logging(
    server_log_path, debug_mode=DEBUG_MODE, logger_name="rgb_scheduler.web_server"
)

# --- Config Loading using shared util ---
config = load_config(get_config_path())
signalrgb_info = get_signalrgb_info(config)
hue_info = get_philips_hue_info(config)


def get_key():
    try:
        with open(secret_path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        server_logger.error("Encryption key not found")
        raise


def decrypt_password(encrypted_data):
    try:
        key = get_key()
        fernet = Fernet(key)
        encrypted_password = base64.urlsafe_b64decode(encrypted_data)
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


# --- Logging redirection ---
class LoggerWriter:
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


# --- Schedule file logic ---
def read_schedule():
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


def determine_next_event(sunrise, sunset):
    now = datetime.now(timezone.utc)
    today_sunrise = sunrise.replace(year=now.year, month=now.month, day=now.day)
    today_sunset = sunset.replace(year=now.year, month=now.month, day=now.day)
    tomorrow_sunrise = today_sunrise + timedelta(days=1)
    if DEBUG_MODE:
        if today_sunrise < now:
            today_sunrise = tomorrow_sunrise
        time_to_sunrise = (today_sunrise - now).total_seconds()
        time_to_sunset = (today_sunset - now).total_seconds()
        if time_to_sunrise < time_to_sunset:
            return "sunrise", today_sunrise, "night"
        else:
            return "sunset", today_sunset, "day"
    else:
        if now < today_sunrise:
            return "sunrise", today_sunrise, "night"
        elif now < today_sunset:
            return "sunset", today_sunset, "day"
        else:
            return "sunrise", tomorrow_sunrise, "night"


# --- Sessions ---
def get_sessions_db():
    try:
        return shelve.open(sessions_db_path, writeback=True)
    except dbm.error as e:
        server_logger.error(f"Failed to open sessions database: {e}")
        try:
            os.remove(sessions_db_path)
            return shelve.open(sessions_db_path, writeback=True)
        except Exception as recovery_error:
            server_logger.critical(
                f"Failed to recover sessions database: {recovery_error}"
            )
            raise


sessions = get_sessions_db()


# --- Available SignalRGB effects and Philips Hue scenes ---
def get_effect_and_scene_names(json_file):
    names = []
    try:
        with open(json_file, "r") as f:
            effect_data = json.load(f)
        for effect in effect_data:
            names.append(effect["name"])
        return names
    except FileNotFoundError:
        server_logger.error(f"{json_file} not found")
        return None, "unknown"
    except json.JSONDecodeError:
        server_logger.error(f"Error decoding {json_file}")
        return None, "unknown"
    except KeyError as e:
        server_logger.error(f"Missing key in {json_file}: {e}")
        return None, "unknown"


# --- Effect toggle logic using shared modules ---
def set_dynamic_effect(effect_type: str):
    import subprocess

    effect = (
        signalrgb_info["daytime_effect"]
        if effect_type == "daytime"
        else signalrgb_info["nighttime_effect"]
    )
    scene_name = (
        hue_info["daytime_scene"]
        if effect_type == "daytime"
        else hue_info["nighttime_scene"]
    )

    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess.Popen(
            [
                "cmd",
                "/c",
                f"start /min signalrgb://effect/apply/{effect}?-silentlaunch-",
            ],
            shell=True,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        toggle_hue(
            hue_info["bridge_ip"],
            hue_info["light_name"],
            hue_info["group_name"],
            hue_info["group_type"],
            scene_name,
            effect_type == "nighttime",
            logger=server_logger,
        )
        server_logger.info(f"{effect_type.capitalize()} effect set")
    except Exception as e:
        server_logger.error(f"Error setting {effect_type} effect: {e}")


def set_manual_effect(effect_name=None, scene_name=None):
    """Set manual effect and/or scene with proper formatting for each system"""
    import subprocess
    from urllib.parse import quote

    try:
        # Handle SignalRGB effect if provided
        if effect_name:
            # SignalRGB needs URL encoding for spaces and special characters
            encoded_effect = quote(effect_name, safe="")
            server_logger.info(
                f"Setting SignalRGB effect: '{effect_name}' (encoded as: {encoded_effect})"
            )

            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.Popen(
                [
                    "cmd",
                    "/c",
                    f"start /min signalrgb://effect/apply/{encoded_effect}?-silentlaunch-",
                ],
                shell=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            server_logger.info(f"SignalRGB effect '{effect_name}' applied successfully")

        # Handle Philips Hue scene if provided
        if scene_name:
            server_logger.info(f"Setting Philips Hue scene: '{scene_name}'")

            set_manual_hue_scene(
                hue_info["bridge_ip"],
                hue_info["group_name"],
                hue_info["group_type"],
                scene_name,
                hue_info["light_name"],
                logger=server_logger,
            )
            server_logger.info(f"Philips Hue scene '{scene_name}' applied successfully")

        # Log the final result
        if effect_name and scene_name:
            server_logger.info(
                f"Manual mode completed: Applied effect '{effect_name}' and scene '{scene_name}'"
            )
        elif effect_name:
            server_logger.info(
                f"Manual mode completed: Applied effect '{effect_name}' only"
            )
        elif scene_name:
            server_logger.info(
                f"Manual mode completed: Applied scene '{scene_name}' only"
            )

    except ValueError as ve:
        # Handle specific Hue errors (group/scene not found)
        server_logger.error(f"Configuration error in manual mode: {ve}")
        raise
    except Exception as e:
        server_logger.error(
            f"Unexpected error in manual mode - effect: '{effect_name}', scene: '{scene_name}', error: {e}"
        )
        raise


# --- HTTP Handler ---
class RgbControlHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        server_logger.info("%s - %s" % (self.address_string(), format % args))

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="RGB Control"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def create_session(self):
        session_id = secrets.token_urlsafe(32)
        try:
            sessions[session_id] = {"created_at": time.time(), "last_used": time.time()}
            sessions.sync()
        except Exception as e:
            server_logger.error(f"Failed to create session: {e}")
            return None
        return session_id

    def validate_session(self, session_id):
        server_logger.debug(f"Attempting to validate session: {session_id}")
        try:
            if session_id in sessions:
                server_logger.debug(f"Session found in database: {session_id}")
                session = sessions[session_id]
                if time.time() - session["created_at"] < 7 * 24 * 60 * 60:
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
        if self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-type", "image/png")
            self.end_headers()
            favicon_path = get_static_path("favicon.png")
            if os.path.exists(favicon_path):
                with open(favicon_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                server_logger.error("Favicon not found")
        elif self.path.startswith("/static/"):
            static_file_path = get_static_path(self.path.lstrip("/static/"))
            if os.path.exists(static_file_path):
                if static_file_path.endswith(".css"):
                    self.send_response(200)
                    self.send_header("Content-type", "text/css")
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"File type not supported")
                    return

                with open(static_file_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")
        elif self.path.startswith("/login"):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            error = query.get("error", [None])[0]
            error_msg = "Invalid username or password" if error == "1" else None

            self.render_login_page(error=error_msg)

        elif self.path == "/logout":
            session_id = None
            if "Cookie" in self.headers:
                cookie = http.cookies.SimpleCookie(self.headers["Cookie"])
                if "session" in cookie:
                    session_id = cookie["session"].value
                    if session_id in sessions:
                        del sessions[session_id]
                        sessions.sync()

            self.send_response(302)
            cookie = http.cookies.SimpleCookie()
            cookie["session"] = ""
            cookie["session"]["path"] = "/"
            cookie["session"]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
            self.send_header("Set-Cookie", cookie["session"].OutputString())
            self.send_header("Location", "/login")
            self.end_headers()

        else:
            session_id = None
            if "Cookie" in self.headers:
                cookie = http.cookies.SimpleCookie(self.headers["Cookie"])
                if "session" in cookie:
                    session_id = cookie["session"].value

            if session_id and self.validate_session(session_id):
                self.handle_authenticated_request()
            else:
                redirect_target = f"/login?next={self.path}"
                self.send_response(302)
                self.send_header("Location", redirect_target)
                self.end_headers()

    def do_POST(self):
        if self.path.startswith("/login"):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            redirect_target = query.get("next", ["/"])[0]

            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode()
            params = parse_qs(post_data)

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if username == USERNAME and password == PASSWORD:
                session_id = self.create_session()
                if session_id is None:
                    self.send_error(500, "Internal Server Error")
                    return

                self.send_response(302)
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
                self.send_header("Location", redirect_target)
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header("Location", "/login?error=1")
                self.end_headers()

    def render_login_page(self, error=None):
        template = jinja_env.get_template("login.html")
        html_content = template.render({"error": error})
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_content.encode())

    def handle_authenticated_request(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/toggle":
            if "mode" in params:
                mode = params["mode"][0]

                if mode in ["day", "night"]:
                    self.server.set_dynamic_effect(
                        "daytime" if mode == "day" else "nighttime"
                    )
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

                elif mode == "manual":
                    # Handle manual mode with effect and/or scene parameters
                    effect_name = params.get("effect", [None])[0]
                    scene_name = params.get("scene", [None])[0]

                    # Validation - at least one must be provided
                    if not effect_name and not scene_name:
                        self.send_error(
                            400,
                            "Manual mode requires at least one effect or scene parameter",
                        )
                        server_logger.warning(
                            f"Manual mode request without parameters from {self.client_address[0]}"
                        )
                        return

                    # Apply the manual settings
                    try:
                        set_manual_effect(effect_name, scene_name)

                        # Send success response
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()

                        # Build description for redirect and logging
                        description_parts = []
                        if effect_name:
                            description_parts.append(f"effect '{effect_name}'")
                        if scene_name:
                            description_parts.append(f"scene '{scene_name}'")
                        description = " and ".join(description_parts)

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
                                window.location.href = "/?mode=manual";
                            </script>
                        </head>
                        <body>
                            <p>Manual settings applied: {description}</p>
                            <p>If you are not redirected, <a href="/?mode=manual">click here</a></p>
                        </body>
                        </html>
                        """
                        self.wfile.write(redirect_script.encode())

                        server_logger.info(
                            f"Manual mode applied by {self.client_address[0]} - {description}"
                        )
                        return

                    except ValueError as ve:
                        # Handle configuration errors (scene/group not found, etc.)
                        self.send_error(400, f"Configuration error: {str(ve)}")
                        server_logger.error(
                            f"Manual mode config error for {self.client_address[0]}: {ve}"
                        )
                        return

                    except Exception as e:
                        self.send_error(
                            500, f"Failed to apply manual settings: {str(e)}"
                        )
                        server_logger.error(
                            f"Manual mode failed for {self.client_address[0]}: {e}"
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
                next_event, next_time, current_mode = determine_next_event(
                    sunrise, sunset
                )
            else:
                next_event = "Not available"
                next_time = now
                current_mode = "day" if 6 <= now.hour < 18 else "night"

            if "mode" in params:
                current_mode = params["mode"][0]

            effect_names = get_effect_and_scene_names(effects_file)
            scene_names = get_effect_and_scene_names(scenes_file)

            if scene_names is not None:
                scene_names.append("Off")

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
                "effect_names": effect_names if effect_names else [],
                "scene_names": scene_names if scene_names else [],
            }

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


def run_server(set_effect_func=set_dynamic_effect):
    web_server_id = str(random.randint(10000, 99999))
    os.environ["WEB_SERVER_ID"] = web_server_id

    if DEBUG_MODE:
        server_logger.debug("Debug mode activated")

    if not verify_certificate():
        raise Exception("Certificate verification failed")
    try:
        clear_old_log_entries(server_log_path, server_logger)

        handler = RgbControlHandler
        server_logger.debug(f"Attempting to start server on port {PORT}")
        httpd = http.server.HTTPServer(("", PORT), handler)
        server_logger.debug("HTTP server created successfully")
        httpd.set_dynamic_effect = set_effect_func

        server_logger.debug("Attempting to create SSL context")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        context.options |= (
            ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_COMPRESSION
            | ssl.OP_CIPHER_SERVER_PREFERENCE
            | ssl.OP_SINGLE_DH_USE
            | ssl.OP_SINGLE_ECDH_USE
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
