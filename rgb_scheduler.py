import os
import subprocess
import time
import logging
from logging.handlers import RotatingFileHandler
import configparser
from datetime import datetime, timedelta
from typing import Tuple, Optional, List, Dict
import sys
import random
import json
from threading import Lock
import multiprocessing
import argparse

import pytz
from astral import LocationInfo
from astral.sun import sun
from phue import Bridge
import psutil
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.pool import ThreadPoolExecutor

from web_server import run_server


DEBUG_MODE = os.environ.get("RGB_SCHEDULER_DEBUG_MODE", "false").lower() == "true"
script_dir = os.path.dirname(os.path.abspath(__file__))
scheduler_log_path = os.path.join(script_dir, "scheduler.log")
scheduler_logger = logging.getLogger("rgb_scheduler")
scheduler_logger.addHandler(logging.NullHandler())
schedule_file = os.path.join(script_dir, "schedule.json")
schedule_lock = Lock()
jobstores = {"default": MemoryJobStore()}
executors = {"default": ThreadPoolExecutor(max_workers=1)}
job_defaults = {
    "coalesce": True,
    "max_instances": 1,
    "misfire_grace_time": None,  # Allow the job to always run, regardless of how late it is
}
scheduler = BackgroundScheduler(
    jobstores=jobstores, executors=executors, job_defaults=job_defaults
)
config = configparser.ConfigParser()
config.read(os.path.join(script_dir, "config.ini"))


def configure_logging(debug_mode: bool = False) -> logging.Logger:
    """Configure logging with a rotating file handler."""
    global scheduler_logger
    logger = scheduler_logger
    logger = logging.getLogger("rgb_scheduler")
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)

    # Remove all handlers associated with the logger object.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    handler = RotatingFileHandler(
        scheduler_log_path,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
    )
    formatter = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    logger.addHandler(handler)

    return logger


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
            scheduler_logger.info(f"Log entries older than {days_to_keep} days cleared")
    except Exception as e:
        scheduler_logger.error(f"Error clearing old log entries: {e}")


try:
    city_name = config.get("location.info", "Name")
    city_region = config.get("location.info", "Region")
    city_timezone = config.get("location.info", "Timezone")
    city_latitude = config.get("location.info", "Latitude")
    city_longitude = config.get("location.info", "Longitude")
    daytime_effect = config.get("signal.rgb", "DaytimeEffect").replace(" ", "%20")
    nighttime_effect = config.get("signal.rgb", "NighttimeEffect").replace(" ", "%20")
    bridge_ip = config.get("philips.hue", "BridgeIp")
    group_name = config.get("philips.hue", "GroupName")
    group_type = config.get("philips.hue", "GroupType")
    light_name = config.get("philips.hue", "Light")
    scene_name = config.get("philips.hue", "Scene")
except Exception as e:
    scheduler_logger.critical(f"Failed to load configuration: {e}")
    raise


def get_sun_times() -> (
    Tuple[Optional[datetime], Optional[datetime], Optional[pytz.timezone]]
):
    """Calculate sunrise and sunset times for the current location."""
    city = LocationInfo(
        name=city_name,
        region=city_region,
        timezone=city_timezone,
        latitude=city_latitude,
        longitude=city_longitude,
    )
    timezone = pytz.timezone(city_timezone)

    try:
        today = datetime.now(timezone).date()
        scheduler_logger.debug(
            f"Calculating sun times for {today} at location {city.name}, {city.region} (lat: {city.latitude}, long: {city.longitude})"
        )

        s = sun(city.observer, date=today, tzinfo=timezone)
        scheduler_logger.debug(f"Raw sun times data: {s}")

        sunrise_time = s.get("sunrise")
        sunset_time = s.get("sunset")

        if not sunrise_time or not sunset_time:
            raise ValueError("Sunrise or sunset time not found")

        scheduler_logger.debug(
            f"Sunrise time: {sunrise_time}, Sunset time: {sunset_time}"
        )
        return sunrise_time, sunset_time, timezone
    except ValueError as ve:
        scheduler_logger.error(f"Value error getting sun times: {ve}")
        return None, None, None
    except Exception as e:
        scheduler_logger.error(f"Unexpected error getting sun times: {e}")
        return None, None, None


def toggle_hue(switch: bool) -> None:
    """Toggle Philips Hue lights."""
    bridge = Bridge(bridge_ip)
    bridge.connect()  # If running for the first time, press the button on the bridge and call connect()
    if not switch:
        bridge.set_light(light_name, "on", False)
    else:
        groups = bridge.get_group()
        group_id_to_set = None
        for group_id, group in groups.items():
            if group["name"] == group_name and group["type"] == group_type:
                group_id_to_set = group_id
                break

        scenes = bridge.get_scene()
        scene_id_to_set = None
        for scene_id, scene in scenes.items():
            if scene["name"] == scene_name:
                scene_id_to_set = scene_id
                break

        if not group_id_to_set or not scene_id_to_set:
            if not group_id_to_set:
                scheduler_logger.warning(
                    f"Group with name '{group_name}' and type '{group_type}' not found"
                )
            if not scene_id_to_set:
                scheduler_logger.warning(f"Scene with name '{scene_name}' not found")
            bridge.set_light(light_name, "on", True)
        else:
            bridge.activate_scene(int(group_id_to_set), scene_id_to_set)


current_effect = None


def get_current_effect():
    """Get the current effect."""
    global current_effect
    return current_effect


def set_effect(effect_type: str) -> None:
    global current_effect
    try:
        effect = daytime_effect if effect_type == "daytime" else nighttime_effect

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
        toggle_hue(effect_type == "nighttime")
        current_effect = effect_type  # Update the global variable
        scheduler_logger.info(f"{effect_type.capitalize()} effect set")
    except subprocess.SubprocessError as e:
        scheduler_logger.error(
            f"Subprocess error when setting {effect_type} effect: {e}"
        )
    except Exception as e:
        scheduler_logger.error(f"Error setting {effect_type} effect: {e}")


def save_schedule(sunrise_time, sunset_time):
    """Save the sunrise and sunset times to a JSON file."""
    with schedule_lock:
        schedule_data = {
            "sunrise": sunrise_time.isoformat() if sunrise_time else None,
            "sunset": sunset_time.isoformat() if sunset_time else None,
            "last_updated": datetime.now(sunrise_time.tzinfo).isoformat(),
        }
        with open(schedule_file, "w") as f:
            json.dump(schedule_data, f)
        scheduler_logger.debug(f"Schedule saved: {schedule_data}")


def get_next_event_time(current_time, sunrise_time, sunset_time):
    if sunrise_time <= current_time < sunset_time:
        return sunset_time, "nighttime"
    elif current_time < sunrise_time:
        return sunrise_time, "daytime"
    else:
        return sunrise_time + timedelta(days=1), "daytime"


def schedule_sun_events():
    global scheduler, DEBUG_MODE, current_effect

    # Get the actual sunrise and sunset times
    sunrise_time, sunset_time, timezone = get_sun_times()
    now = datetime.now(timezone)

    if DEBUG_MODE:
        debug_cycle_minutes = 4
        day_portion = 0.5  # 50% of the cycle is day

        current_cycle_minute = (now.hour * 60 + now.minute) % debug_cycle_minutes
        cycle_start = now - timedelta(minutes=current_cycle_minute)

        debug_sunrise = cycle_start
        debug_sunset = cycle_start + timedelta(
            minutes=debug_cycle_minutes * day_portion
        )

        if current_cycle_minute < (debug_cycle_minutes * day_portion):
            current_effect = "daytime"
            next_effect = "nighttime"
            next_event_time = debug_sunset
        else:
            current_effect = "nighttime"
            next_effect = "daytime"
            next_event_time = debug_sunrise + timedelta(minutes=debug_cycle_minutes)

        next_next_event_time = next_event_time + timedelta(
            minutes=debug_cycle_minutes * day_portion
            if next_effect == "daytime"
            else debug_cycle_minutes * (1 - day_portion)
        )

        scheduler_logger.debug(f"Debug mode active. Current time: {now.isoformat()}")
        scheduler_logger.debug(
            f"Debug Sunrise: {debug_sunrise.isoformat()}, Debug Sunset: {debug_sunset.isoformat()}"
        )
        scheduler_logger.debug(
            f"Next event time: {next_event_time.isoformat()}, Next next event time: {next_next_event_time.isoformat()}"
        )
        scheduler_logger.debug(
            f"Debug cycle length: {debug_cycle_minutes} minutes (Day: {debug_cycle_minutes * day_portion} minutes, Night: {debug_cycle_minutes * (1-day_portion)} minutes)"
        )
        scheduler_logger.debug(
            f"Current effect: {current_effect}, Next effect: {next_effect}"
        )

        # Save the schedule for the immediate next two events
        if current_effect == "daytime":
            save_schedule(next_next_event_time, next_event_time)
        else:
            save_schedule(next_event_time, next_next_event_time)

    else:
        # Normal mode logic
        if not sunrise_time or not sunset_time:
            scheduler_logger.warning("No sun times available to schedule events")
            # Schedule default times for high latitude regions
            default_sunrise = now.replace(hour=6, minute=0, second=0, microsecond=0)
            default_sunset = now.replace(hour=18, minute=0, second=0, microsecond=0)
            sunrise_time, sunset_time = default_sunrise, default_sunset
            scheduler_logger.info(
                f"Default times scheduled: Daytime at {default_sunrise.time()}, Nighttime at {default_sunset.time()}"
            )

        next_event_time, next_effect = get_next_event_time(
            now, sunrise_time, sunset_time
        )
        current_effect = "daytime" if sunrise_time <= now < sunset_time else "nighttime"

        # Save the schedule
        save_schedule(sunrise_time, sunset_time)

    # Set the current effect
    set_effect(current_effect)
    scheduler_logger.info(f"Current effect set to: {current_effect}")

    scheduler_logger.info(f"Next event scheduled for: {next_event_time}")
    scheduler_logger.info(f"Next effect will be: {next_effect}")

    # Schedule the next event using APScheduler
    try:
        scheduler.add_job(
            execute_sun_event,
            trigger="date",
            run_date=next_event_time,
            id="sun_events",
            args=[next_event_time, next_effect],
            replace_existing=True,
        )
        scheduler_logger.debug(f"New job added for {next_event_time}")
        scheduler_logger.debug(f"All jobs: {scheduler.get_jobs()}")
    except Exception as e:
        scheduler_logger.error(f"Error adding job: {e}")
        # Attempt to reschedule in 5 minutes
        scheduler.add_job(
            schedule_sun_events,
            "date",
            run_date=now + timedelta(minutes=5),
            id="retry_sun_events",
        )


def execute_sun_event(scheduled_time, effect_to_set):
    try:
        scheduler_logger.debug(f"Executing sun event scheduled for {scheduled_time}")
        current_effect = get_current_effect()
        if current_effect != effect_to_set:
            set_effect(effect_to_set)
            scheduler_logger.info(f"Effect changed to: {effect_to_set}")
        else:
            scheduler_logger.info(f"Effect remains: {effect_to_set}")
        schedule_sun_events()  # Reschedule the next event
    except Exception as e:
        scheduler_logger.error(f"Error executing sun event: {e}")
        # Attempt to reschedule
        try:
            schedule_sun_events()
        except Exception as e:
            scheduler_logger.critical(f"Failed to reschedule sun events: {e}")


def start_scheduler():
    global scheduler, current_effect

    if scheduler.running:
        scheduler_logger.debug("Scheduler is already running")
    else:
        scheduler.configure(job_defaults={"coalesce": True, "max_instances": 1})
        scheduler.start()
        scheduler_logger.debug("Scheduler started")

    schedule_sun_events()

    if DEBUG_MODE:
        scheduler_logger.debug("Scheduler started in debug mode")
        scheduler_logger.debug(f"Scheduler state: {scheduler.state}")
        scheduler_logger.debug(f"Scheduled jobs: {scheduler.get_jobs()}")


def wrapped_run_server(set_effect):
    """Wrapper used as a target for web server multiprocessing."""
    run_server(set_effect)


def run_web_server(set_effect):
    """Run the web server in a separate process."""
    process = multiprocessing.Process(target=wrapped_run_server, args=(set_effect,))
    process.start()
    return process


def find_processes(env_var_names: List[str]) -> List[Dict]:
    """Find all processes that use any of the specified environment variables."""
    matching_processes = []
    for proc in psutil.process_iter(["pid", "name", "environ", "cmdline"]):
        try:
            proc_env = proc.info["environ"]
            proc_cmdline = proc.info["cmdline"]
            if proc_env and any(var_name in proc_env for var_name in env_var_names):
                proc_info = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "cmdline": " ".join(proc_cmdline) if proc_cmdline else "",
                    "env_vars": {
                        var: proc_env.get(var)
                        for var in env_var_names
                        if var in proc_env
                    },
                }
                matching_processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return matching_processes


def terminate_processes(processes: List[Dict]) -> List[Dict]:
    """Terminate the given processes and return their status."""
    for proc_info in processes:
        try:
            process = psutil.Process(proc_info["pid"])
            process.terminate()
            proc_info["terminated"] = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_info["terminated"] = False

    # Wait for processes to terminate
    time.sleep(3)

    # Check if processes have ended and force kill if necessary
    for proc_info in processes:
        if proc_info["terminated"]:
            try:
                process = psutil.Process(proc_info["pid"])
                if process.is_running():
                    process.kill()
                    proc_info["status"] = "force killed"
                else:
                    proc_info["status"] = "ended"
            except psutil.NoSuchProcess:
                proc_info["status"] = "ended"
            except psutil.AccessDenied:
                proc_info["status"] = "termination failed (access denied)"
        else:
            proc_info["status"] = "termination failed"

    return processes


def is_script_running() -> bool:
    """Check if the script is already running."""
    env_vars_to_check = ["RGB_SCHEDULER_ID"]
    current_script = os.path.abspath(__file__)
    current_pid = os.getpid()
    running_processes = find_processes(env_vars_to_check)

    for proc in running_processes:
        if current_script in proc["cmdline"] and proc["pid"] != current_pid:
            scheduler_logger.info(
                f"Found running instance: PID {proc['pid']}, Command: {proc['cmdline']}"
            )
            return True

    scheduler_logger.info("No other running instance found.")
    return False


def main() -> None:
    """Main function to run the scheduler and start the web server."""
    global DEBUG_MODE, scheduler_logger

    parser = argparse.ArgumentParser(
        description="RGB light scheduler based on sun times"
    )
    parser.add_argument(
        "-k",
        "--kill",
        action="store_true",
        help="Kill all processes related to the script",
    )
    parser.add_argument(
        "-t",
        "--toggle",
        choices=["day", "night"],
        help="Manually set day or night mode",
    )
    parser.add_argument(
        "-w",
        "--wakeup",
        action="store_true",
        help="Trigger wake-up actions",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Run in debug mode mode",
    )
    args = parser.parse_args()

    if args.debug:
        rgb_scheduler_id = str(random.randint(10000, 99999))
        os.environ["RGB_SCHEDULER_ID"] = rgb_scheduler_id
        os.environ["RGB_SCHEDULER_DEBUG_MODE"] = "true"
        DEBUG_MODE = True

    scheduler_logger = configure_logging(debug_mode=DEBUG_MODE)
    if DEBUG_MODE:
        scheduler_logger.debug("Debug mode activated")

    if args.kill:
        env_vars_to_terminate = ["RGB_SCHEDULER_ID", "WEB_SERVER_ID"]
        processes_to_terminate = find_processes(env_vars_to_terminate)
        terminated = terminate_processes(processes_to_terminate)

        if terminated:
            scheduler_logger.info(
                f"Attempted to terminate {len(terminated)} process(es):"
            )
            for proc in terminated:
                env_vars_str = ", ".join(
                    [f"{var}: {value}" for var, value in proc["env_vars"].items()]
                )
                scheduler_logger.info(
                    f"PID: {proc['pid']}, Name: {proc['name']}, Status: {proc['status']} [{env_vars_str}]"
                )

            scheduler_logger.info("Process termination attempts completed")
            sys.exit(0)
        else:
            scheduler_logger.info("No matching processes found to terminate")

    elif args.toggle:
        set_effect("daytime" if args.toggle == "day" else "nighttime")
        scheduler_logger.info(f"Toggled to {args.toggle} mode")

    elif args.wakeup:
        scheduler_logger.info("System woke up from sleep.")
        if is_script_running():
            if not scheduler.running:
                scheduler_logger.info("Scheduler stopped running. Restarting...")
                time.sleep(5)  # Add a small delay to ensure system is fully operational
                start_scheduler()
        else:
            scheduler_logger.warning(
                "Wakeup triggered, but the main script is not running."
            )

    else:
        if is_script_running():
            scheduler_logger.warning("The script is already running. Exiting.")
            sys.exit(0)

        try:
            rgb_scheduler_id = str(random.randint(10000, 99999))
            os.environ["RGB_SCHEDULER_ID"] = rgb_scheduler_id

            clear_old_log_entries(scheduler_log_path)
            start_scheduler()
            server_process = run_web_server(set_effect)

            scheduler_logger.info(
                f"Main process started successfully, RGB_SCHEDULER_ID: {rgb_scheduler_id}"
            )

            check_interval = timedelta(minutes=5)
            last_check = datetime.now(pytz.timezone(city_timezone))

            while True:
                time.sleep(60)  # Check every minute
                now = datetime.now(pytz.timezone(city_timezone))

                if now - last_check >= check_interval:
                    last_check = now
                    if not scheduler.running:
                        scheduler_logger.warning(
                            "Scheduler stopped running. Restarting..."
                        )
                        start_scheduler()
                    else:
                        scheduler_logger.debug("Scheduler still running.")

                if DEBUG_MODE:
                    scheduler_logger.debug(
                        f"Main loop check - Current time: {now.isoformat()}"
                    )
                    scheduler_logger.debug(
                        f"Main loop check - Scheduler running: {scheduler.running}"
                    )
                    jobs = scheduler.get_jobs()
                    scheduler_logger.debug(f"Main loop check - Scheduled jobs: {jobs}")

                    for job in jobs:
                        scheduler_logger.debug(
                            f"Job {job.id} next run time: {job.next_run_time}"
                        )

        except Exception as e:
            scheduler_logger.critical(f"Script terminated unexpectedly: {e}")
        finally:
            scheduler.shutdown()
            if "server_process" in locals():
                server_process.terminate()
            logging.shutdown()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        scheduler_logger.info("Script terminated by user")
    except Exception as e:
        scheduler_logger.critical(f"Unhandled exception in main: {e}")
        sys.exit(1)
