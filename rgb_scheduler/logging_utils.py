import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta


def configure_logging(
    log_path: str, debug_mode: bool = False, logger_name: str = "rgb_scheduler"
) -> logging.Logger:
    """
    Configure and return a logger with a rotating file handler.

    Args:
        log_path: Path to the log file.
        debug_mode: If True, sets logging level to DEBUG, else INFO.
        logger_name: Name of the logger (module-specific).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)

    # Remove all handlers associated with this logger (not ancestor/root handlers!)
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Prevent adding duplicate file handlers (important if configure_logging called multiple times)
    if not any(
        isinstance(h, RotatingFileHandler)
        and getattr(h, "baseFilename", None) == log_path
        for h in logger.handlers
    ):
        handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        logger.addHandler(handler)

    # Prevent log propagation to parent/root loggers
    logger.propagate = False

    return logger


def clear_old_log_entries(log_file: str, logger, days_to_keep: int = 30) -> None:
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
                    lines_kept.append(line)
            file.writelines(lines_kept)

        if lines_cleared:
            logger.info(f"Log entries older than {days_to_keep} days cleared")
    except Exception as e:
        logger.error(f"Error clearing old log entries: {e}")
