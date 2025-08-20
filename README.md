# RGB Scheduler

**RGB Scheduler** is a modular Python application that automatically adjusts your computer’s RGB lighting effects (SignalRGB & Philips Hue) based on sunrise and sunset times. It includes a web interface for manual control and status monitoring.

---

## Features

- **Automatic RGB scheduling:** Switches between custom day/night lighting effects based on sun events.
- **Web interface:** Secure HTTPS server for manual toggling, viewing schedules, and remote control.
- **SignalRGB & Philips Hue support:** Integrated control for both eco-systems (effect and scene activation).
- **Process & wake event detection:** Automatically starts/stops based on system events and running applications.
- **Extensible & modular:** All device logic is encapsulated in Python modules for easy extension and maintenance.

---

## Requirements

- [Python 3.x](https://www.python.org/)
- Windows 10 or newer (for process detection and wake handling)
- [SignalRGB](https://signalrgb.com/) (for PC RGB control)
- [Philips Hue Bridge & lights](https://www.philips-hue.com/)
- [OpenSSL](https://openssl-library.org/) (for HTTPS certificate)
- Required Python packages (`pip install -r requirements.txt`)

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/janiaul/rgb-scheduler.git
   ```
2. **(Optional) Set your preferred install path:**  
   If not using the default `C:\Users\%USERNAME%\Scripts\rgb-scheduler\`, update these scripts:
   - `run_hidden.vbs`
   - `run_task.bat`
   - `wake_up_handler.bat`

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Generate a password for web access:**
   ```bash
   python -m scripts.generate_password
   ```
   Use the generated encrypted password in your `config.ini`.

5. **Configure your settings:**
   - Edit `config.ini` for:
     - Web server port and user credentials
     - Location info (for sun calculations)
     - SignalRGB effect names
     - Philips Hue Bridge IP and group/scene names

6. **Generate a self-signed HTTPS certificate:**
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```
   Place both `key.pem` and `cert.pem` in the project data directory.

7. **Set up Windows Tasks:**
   - **Startup:** Schedule `run_hidden.vbs` to run at logon
   - **Wake-up:** Schedule `wake_up_handler.bat` to run on resume from sleep

8. **Register with Hue Bridge:**  
   On first run, press the Hue Bridge button to authorize the app.

---

## Usage

- The scheduler runs automatically at startup, and after wake events.
- Effect switching is triggered by sun events or manual web controls.
- Access the web interface at `https://localhost:8000` (or your configured port).
- To turn off the SignalRGB controlled lights, set the appropriate effect to "[Good Night!](https://marketplace.signalrgb.com/effect/good-night)" in the configuration file.
- To turn off the Hue light, set the appropriate scene to "Off" in the configuration file.

> **Tip:** If you change the install directory, update all scripts and scheduled tasks accordingly.

**Web Interface:**
1. Open your browser to the configured address/port.
2. Login with your credentials.
3. View current effect/schedule or manually toggle day/night mode.

---

## Project Structure

- `rgb_scheduler/`
  - `scheduler.py` – Main scheduler logic
  - `hue_utils.py` – Philips Hue integration (scene/group utilities)
  - `signalrgb_utils.py` – SignalRGB effect logic
  - `web_server.py` – Web server for remote/manual control
  - `config_utils.py` – Configuration loaders/parsers
  - `logging_utils.py` – Logging setup and maintenance
  - `process_utils.py` – Process/startup/wake event utilities
  - `path_utils.py` – Cross-platform path helpers
- `scripts/`
  - `generate_password.py` – Password encryption tool
- `run_task.bat` – Batch script for startup
- `wake_up_handler.bat` – Batch script for wake-up
- `run_hidden.vbs` – VBScript for silent startup
- `config.ini` – Main configuration file
- `requirements.txt` – Python dependencies
- `web_server_template.html` – Customizable web UI template

---

## Security

- **HTTPS:** Web server runs over TLS (self-signed cert included by default)
- **Authentication:** Web access requires login; passwords are encrypted in `config.ini`
- **Logs:** All access and effect changes are logged in `scheduler.log` and `server.log`

---

## Customization

- **Web UI:** Edit `index.html` and `main.css` for appearance and layout.
- **Effect logic:** Add new device or effect support by extending the appropriate utility modules.

---

## Troubleshooting

- Check `scheduler.log` and `server.log` for errors.
- Common setup issues:
  - SSL certificate not generated or misplaced
  - Encrypted password in `config.ini` doesn’t match
  - Required Python packages not installed
  - Windows scheduled tasks not configured correctly
  - Trying to use an effect or a scene that's not installed

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

## License

This project is licensed under a custom license. See the `LICENSE` file for details.