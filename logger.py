"""Logging setup. Passwords and master passwords are NEVER written to the log."""

import logging
from logging.handlers import RotatingFileHandler


def get_logger(log_file=None) -> logging.Logger:
    """Configure the package logger (rotating file, 100 KB x 2 backups)."""
    logger = logging.getLogger("securevault")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if log_file is None:
        logger.addHandler(logging.NullHandler())
        return logger
    handler = RotatingFileHandler(log_file, maxBytes=100_000, backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
    logger.addHandler(handler)
    return logger
