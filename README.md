# RGB Scheduler

RGB Scheduler is a Python-based application that automatically adjusts your computers' RGB lighting effects based on sunrise and sunset times. It also provides a web interface for manual control and viewing schedule information.

## Features

- Automatically switches between day (RGBs off) and night (RGBs on) lighting effects based on sun events
- Web interface for manual control and viewing schedule information
- Secure HTTPS web server with authentication
- Supports SignalRGB for RGB effects and Philips Hue for lighting control
- Automatically starts when specific processes are detected
- Handles system wake-up events to reschedule RGB changes

## Requirements

- [Python](https://www.python.org/) 3.x
- Windows 10 or newer (for automatic startup and wake-up handling)
- [SignalRGB](https://signalrgb.com/) and [Hue Sync](https://www.philips-hue.com/en-us/explore-hue/propositions/entertainment/sync-with-pc)
- Philips Hue Bridge and compatible lights
- [OpenSSL](https://openssl-library.org/) (for generating self-signed certificates)

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/janiaul/rgb-scheduler.git
   ```

2. **Important:** The default installation directory is `C:\Users\%USERNAME%\Scripts\rgb-scheduler\`. If you want to use a different location:
   - Update the following files with the new path:
     * `run_hidden.vbs`
     * `run_task.bat`
     * `wake_up_handler.bat`

3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Generate an encrypted password for the web interface:
   ```bash
   python generate_password.py
   ```
   Follow the prompts to enter a password. The script will generate an encrypted version to use in the config file.

5. Configure the `config.ini` file with your specific settings:
   - Web server port and credentials (use the encrypted password generated in step 4)
   - Location information for sun calculations
   - SignalRGB effect names
   - Philips Hue Bridge IP and light settings

6. Generate a self-signed SSL certificate for the web server:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```
   Follow the prompts to enter information for your certificate.

7. Set up the startup script:
   - Add `run_hidden.vbs` as a Windows scheduled task to run at startup

8. Set up the wake-up handler:
   - Add `wake_up_handler.bat` as a Windows scheduled task to run when the system wakes up from sleep

9. Before running for the first time, press the button on the Philips Hue Bridge to register the application

## Usage

The application will start automatically on system startup when the required processes (SignalRGB and HueSync) are detected. It will also handle system wake-up events to reschedule RGB changes.

> **Note:** If you changed the installation directory in step 2 of the installation process, ensure that your startup scripts and scheduled tasks are pointing to the correct location.

To access the web interface:

1. Open a web browser and navigate to `https://localhost:8000` (or the port you specified in the config file)
2. Log in using the credentials set in the config file
3. View the current schedule and manually toggle between day and night modes if desired

## Files

- `rgb_scheduler.py`: Main script for scheduling and applying RGB effects
- `web_server.py`: Web server for the control interface
- `run_task.bat`: Batch script to check for required processes and start the scheduler
- `wake_up_handler.bat`: Batch script to handle system wake-up events
- `config.ini`: Configuration file for various settings
- `generate_password.py`: Script to generate encrypted passwords for the config file
- `web_server_template.html`: HTML template for the web interface
- `run_hidden.vbs`: VBScript to run the scheduler at system startup

## Security

- The web server uses HTTPS with a self-signed certificate
- Authentication is required to access the web interface
- Passwords are encrypted in the configuration file

## Customization

The web interface can be customized by modifying the `web_server_template.html` file. This file contains the HTML structure and embedded styling for the web GUI.

## Troubleshooting

Check the log files (`scheduler.log` and `server.log`) for any error messages or unexpected behavior.

If you encounter issues with the web interface, ensure that:
1. The self-signed certificate is properly generated and located in the script directory.
2. The encrypted password in `config.ini` matches the one you generated using `generate_password.py`.
3. The required Python packages are installed correctly.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under a custom license. See the LICENSE file for details.