import os
import sys
import time
import json
import random
import argparse
import multiprocessing
from threading import Lock
from datetime import datetime, timedelta

import pytz
from astral import LocationInfo
from astral.sun import sun
import win32api
import psutil

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.pool import ThreadPoolExecutor

try:
    from rgb_scheduler.config_utils import (
        load_config,
        get_location_info,
        get_signalrgb_info,
        get_philips_hue_info,
    )
    from rgb_scheduler.hue_utils import (
        toggle_hue,
        save_scenes_for_default_group_to_file,
    )
    from rgb_scheduler.signalrgb_utils import (
        apply_signalrgb_effect,
        save_signalrgb_effects_to_file,
    )
    from rgb_scheduler.logging_utils import configure_logging, clear_old_log_entries
    from rgb_scheduler.process_utils import (
        find_main_process,
        find_matching_processes,
        terminate_processes,
        create_wakeup_event,
        set_wakeup_event,
        wait_for_wakeup_event,
    )
    from rgb_scheduler.web_server import run_server
    from rgb_scheduler.path_utils import get_log_path, get_data_path, get_config_path
except ImportError:
    print(
        "Error: Cannot import utils. Run this script from the project root with: python -m rgb_scheduler.scheduler"
    )
    sys.exit(1)

WAKEUP_EVENT = "Global\\RGBSchedulerWakeupEvent"
scheduler_log_path = get_log_path("scheduler.log")
schedule_file = get_data_path("schedule.json")
schedule_lock = Lock()
jobstores = {"default": MemoryJobStore()}
executors = {"default": ThreadPoolExecutor(max_workers=1)}
job_defaults = {"coalesce": True, "max_instances": 1, "misfire_grace_time": None}
scheduler = BackgroundScheduler(
    jobstores=jobstores, executors=executors, job_defaults=job_defaults
)

config = load_config(get_config_path())
location_info = get_location_info(config)
signalrgb_info = get_signalrgb_info(config)
hue_info = get_philips_hue_info(config)

DEBUG_MODE = os.environ.get("RGB_SCHEDULER_DEBUG_MODE", "false").lower() == "true"
scheduler_logger = configure_logging(
    scheduler_log_path, debug_mode=DEBUG_MODE, logger_name="rgb_scheduler"
)

try:
    city_name = location_info["name"]
    city_region = location_info["region"]
    city_timezone = location_info["timezone"]
    city_latitude = location_info["latitude"]
    city_longitude = location_info["longitude"]
    daytime_effect = signalrgb_info["daytime_effect"]
    nighttime_effect = signalrgb_info["nighttime_effect"]
    bridge_ip = hue_info["bridge_ip"]
    group_name = hue_info["group_name"]
    group_type = hue_info["group_type"]
    light_name = hue_info["light_name"]
    daytime_scene = hue_info["daytime_scene"]
    nighttime_scene = hue_info["nighttime_scene"]
except Exception as e:
    scheduler_logger.critical(f"Failed to load configuration: {e}")
    raise

current_effect = None


def get_sun_times():
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


def get_current_effect():
    global current_effect
    return current_effect


def set_effect(effect_type: str) -> None:
    global current_effect
    try:
        effect = daytime_effect if effect_type == "daytime" else nighttime_effect
        scene_name = daytime_scene if effect_type == "daytime" else nighttime_scene

        apply_signalrgb_effect(effect, logger=scheduler_logger)
        toggle_hue(
            bridge_ip,
            light_name,
            group_name,
            group_type,
            scene_name,
            effect_type == "nighttime",
            logger=scheduler_logger,
        )
        current_effect = effect_type
        scheduler_logger.info(f"{effect_type.capitalize()} effect set")
    except Exception as e:
        scheduler_logger.error(f"Error setting {effect_type} effect: {e}")


def save_schedule(sunrise_time, sunset_time):
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

    sunrise_time, sunset_time, timezone = get_sun_times()
    now = datetime.now(timezone)

    if DEBUG_MODE:
        debug_cycle_minutes = 4
        day_portion = 0.5
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
            f"Debug cycle length: {debug_cycle_minutes} minutes (Day: {debug_cycle_minutes * day_portion} minutes, Night: {debug_cycle_minutes * (1 - day_portion)} minutes)"
        )
        scheduler_logger.debug(
            f"Current effect: {current_effect}, Next effect: {next_effect}"
        )
        if current_effect == "daytime":
            save_schedule(next_next_event_time, next_event_time)
        else:
            save_schedule(next_event_time, next_next_event_time)
    else:
        if not sunrise_time or not sunset_time:
            scheduler_logger.warning("No sun times available to schedule events")
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
        save_schedule(sunrise_time, sunset_time)

    set_effect(current_effect)
    scheduler_logger.info(f"Next event scheduled for: {next_event_time}")
    scheduler_logger.info(f"Next effect will be: {next_effect.capitalize()}")

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
        scheduler.add_job(
            schedule_sun_events,
            "date",
            run_date=now + timedelta(minutes=5),
            id="retry_sun_events",
        )


def execute_sun_event(scheduled_time, effect_to_set):
    try:
        scheduler_logger.debug(f"Executing sun event scheduled for {scheduled_time}")
        current_eff = get_current_effect()
        if current_eff != effect_to_set:
            set_effect(effect_to_set)
            scheduler_logger.info(f"Effect changed to: {effect_to_set}")
        else:
            scheduler_logger.info(f"Effect remains: {effect_to_set}")
        schedule_sun_events()
    except Exception as e:
        scheduler_logger.error(f"Error executing sun event: {e}")
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
    run_server(set_effect)


def run_web_server(set_effect):
    process = multiprocessing.Process(target=wrapped_run_server, args=(set_effect,))
    process.start()
    return process


def is_script_running():
    env_vars_to_check = ["RGB_SCHEDULER_ID"]
    current_script = os.path.abspath(__file__)
    current_pid = os.getpid()
    running_processes = find_matching_processes(env_vars_to_check, scheduler_logger)
    for proc in running_processes:
        if current_script in proc["cmdline"] and proc["pid"] != current_pid:
            scheduler_logger.info(
                f"Found running instance: PID {proc['pid']}, Command: {proc['cmdline']}"
            )
            return True
    scheduler_logger.info("No other running instance found")
    return False


def handle_wakeup():
    scheduler_logger.info("System woke up from sleep")
    current_pid = os.getpid()
    current_script = os.path.abspath(__file__)
    current_rgb_scheduler_id = os.environ.get("RGB_SCHEDULER_ID")
    scheduler_logger.info(
        f"Current process: PID {current_pid}, Script: {current_script}, RGB_SCHEDULER_ID: {current_rgb_scheduler_id}"
    )
    main_process = find_main_process(current_script, scheduler_logger)
    if main_process:
        set_wakeup_event(WAKEUP_EVENT, scheduler_logger)
        scheduler_logger.info(
            f"Wakeup event set for the running instance (PID: {main_process.pid})"
        )
    else:
        scheduler_logger.warning("Main process not found by find_main_process function")
        script_name = os.path.basename(current_script).lower()
        matching_processes = []
        for proc in psutil.process_iter(["pid", "name", "cmdline", "environ"]):
            try:
                if script_name in " ".join(proc.cmdline()).lower():
                    proc_info = {
                        "pid": proc.pid,
                        "cmdline": " ".join(proc.cmdline()),
                        "env": proc.environ().get("RGB_SCHEDULER_ID"),
                    }
                    matching_processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        scheduler_logger.info(
            f"Found {len(matching_processes)} processes running the script:"
        )
        for proc in matching_processes:
            scheduler_logger.info(
                f"PID: {proc['pid']}, CMD: {proc['cmdline']}, RGB_SCHEDULER_ID: {proc['env']}"
            )
        scheduler_logger.warning(
            "Wakeup triggered, but the main script was not identified"
        )


def handle_termination():
    scheduler_logger.info("Terminating processes...")
    env_vars_to_terminate = ["RGB_SCHEDULER_ID", "WEB_SERVER_ID"]
    processes_to_terminate = find_matching_processes(
        env_vars_to_terminate, scheduler_logger
    )
    terminated = terminate_processes(processes_to_terminate, scheduler_logger)
    if terminated:
        scheduler_logger.info(f"Attempted to terminate {len(terminated)} process(es):")
        for proc in terminated:
            env_vars_str = ", ".join(
                [f"{var}: {value}" for var, value in proc["env_vars"].items()]
            )
            scheduler_logger.info(
                f"PID: {proc['pid']}, NAME: {proc['name']}, STATUS: {proc.get('status', 'unknown')}, ENV: [{env_vars_str}]"
            )
        scheduler_logger.info("Process termination attempts completed")
    else:
        scheduler_logger.info("No matching processes found to terminate")


def main(args: argparse.Namespace) -> None:
    global scheduler, DEBUG_MODE, scheduler_logger

    if args.debug:
        os.environ["RGB_SCHEDULER_DEBUG_MODE"] = "true"
        DEBUG_MODE = True

    scheduler_logger = configure_logging(scheduler_log_path, debug_mode=DEBUG_MODE)
    if DEBUG_MODE:
        scheduler_logger.debug("Debug mode activated")

    try:
        save_scenes_for_default_group_to_file()
        save_signalrgb_effects_to_file()
        scheduler_logger.info("Updated scenes.json and effects.json")
    except Exception as e:
        scheduler_logger.error(f"Failed to update scenes/effects JSON: {e}")

    if args.kill:
        handle_termination()
        sys.exit(0)

    elif args.wakeup:
        handle_wakeup()

    elif args.toggle:
        set_effect("daytime" if args.toggle == "day" else "nighttime")
        scheduler_logger.info(f"Toggled to {args.toggle} mode")

    else:
        scheduler_logger.info("Starting RGB Scheduler...")

        if is_script_running():
            scheduler_logger.warning("The script is already running, exiting")
            sys.exit(0)

        try:
            rgb_scheduler_id = str(random.randint(10000, 99999))
            os.environ["RGB_SCHEDULER_ID"] = rgb_scheduler_id
            scheduler_logger.info(
                f"Main process started, RGB_SCHEDULER_ID: {rgb_scheduler_id}"
            )
            clear_old_log_entries(scheduler_log_path, scheduler_logger)
            start_scheduler()
            server_process = run_web_server(set_effect)
            wakeup_event = create_wakeup_event(WAKEUP_EVENT, scheduler_logger)
            if not wakeup_event:
                raise Exception("Failed to create wakeup event")
            alert_mode = False
            alert_mode_duration = 60
            alert_mode_start = None
            check_interval = timedelta(minutes=5)
            last_check = datetime.now(pytz.timezone(city_timezone))
            scheduler_logger.info("Entering main loop")
            loop_count = 0
            while True:
                if alert_mode:
                    wait_time = 1000
                    if alert_mode_start is None:
                        alert_mode_start = time.time()
                        scheduler_logger.info("Entered alert mode")
                    elif time.time() - alert_mode_start > alert_mode_duration:
                        alert_mode = False
                        alert_mode_start = None
                        scheduler_logger.info("Exiting alert mode")
                else:
                    wait_time = 60000
                event_signaled = wait_for_wakeup_event(
                    WAKEUP_EVENT, wait_time, scheduler_logger
                )
                if event_signaled:
                    scheduler_logger.info(
                        "Wakeup event detected. Checking scheduler..."
                    )
                    if not scheduler.running:
                        scheduler_logger.warning("Scheduler not running. Restarting...")
                        start_scheduler()
                    else:
                        scheduler_logger.info("Scheduler is running")
                        schedule_sun_events()
                    alert_mode = True
                    alert_mode_start = time.time()
                elif alert_mode:
                    scheduler_logger.debug("In alert mode. Checking scheduler...")
                    if not scheduler.running:
                        scheduler_logger.warning("Scheduler not running. Restarting...")
                        start_scheduler()
                    else:
                        scheduler_logger.debug("Scheduler is running")
                now = datetime.now(pytz.timezone(city_timezone))
                if now - last_check >= check_interval:
                    last_check = now
                    if not scheduler.running:
                        scheduler_logger.warning(
                            "Scheduler stopped running. Restarting..."
                        )
                        start_scheduler()
                    else:
                        loop_count += 1
                        if loop_count % 12 == 0:
                            scheduler_logger.info(
                                "Hourly check: Scheduler running normally"
                            )
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
            scheduler_logger.info("Shutting down")
            scheduler.shutdown()
            if "server_process" in locals():
                server_process.terminate()
            if "wakeup_event" in locals():
                win32api.CloseHandle(wakeup_event)
            import logging as pylogging

            pylogging.shutdown()


if __name__ == "__main__":
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
        "-w", "--wakeup", action="store_true", help="Trigger wake-up actions"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Run in debug mode")
    args = parser.parse_args()

    try:
        main(args)
    except (KeyboardInterrupt, SystemExit):
        scheduler_logger.info("Script terminated by user")
        sys.exit(0)
    except Exception as e:
        scheduler_logger.critical(f"Unhandled exception in main: {e}")
        sys.exit(1)
