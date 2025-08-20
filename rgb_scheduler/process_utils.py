import os
import time
import psutil
import win32event
import win32api


def find_main_process(script_path, logger):
    current_pid = os.getpid()
    script_name = os.path.basename(script_path).lower()
    logger.debug(f"Current process: PID {current_pid}")
    logger.debug(f"Searching for process with script: {script_path}")

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            proc_cmdline = " ".join(proc.cmdline()).lower()
            if (
                script_name in proc_cmdline
                and "multiprocessing-fork" not in proc_cmdline
                and proc.pid != current_pid
            ):
                logger.info(f"Found main process: PID {proc.pid}")
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    logger.warning("Main process not found")
    return None


def find_matching_processes(env_var_names, logger):
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


def terminate_processes(processes, logger):
    for proc_info in processes:
        try:
            process = psutil.Process(proc_info["pid"])
            process.terminate()
            proc_info["terminated"] = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_info["terminated"] = False

    time.sleep(3)

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


def create_wakeup_event(event_name, logger):
    try:
        event = win32event.CreateEvent(None, False, False, event_name)
        logger.debug(f"Wakeup event created: {event_name}")
        return event
    except Exception as e:
        logger.error(f"Failed to create wakeup event: {e}")
        return None


def set_wakeup_event(event_name, logger):
    try:
        event = win32event.OpenEvent(win32event.EVENT_MODIFY_STATE, False, event_name)
        win32event.SetEvent(event)
        win32api.CloseHandle(event)
        logger.info(f"Wakeup event set: {event_name}")
    except Exception as e:
        logger.error(f"Failed to set wakeup event: {e}")


def wait_for_wakeup_event(event_name, timeout_ms, logger):
    try:
        event = win32event.OpenEvent(win32event.SYNCHRONIZE, False, event_name)
        result = win32event.WaitForSingleObject(event, timeout_ms)
        win32api.CloseHandle(event)

        if result == win32event.WAIT_OBJECT_0:
            logger.info("Wakeup event signaled")
            return True
        elif result == win32event.WAIT_TIMEOUT:
            logger.debug("Wakeup event wait timed out")
            return False
        else:
            logger.warning(f"Unexpected result from WaitForSingleObject: {result}")
            return False
    except Exception as e:
        logger.error(f"Error waiting for wakeup event: {e}")
        return False
