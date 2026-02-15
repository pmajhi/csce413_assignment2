#!/usr/bin/env python3

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logger(log_path: str = "/app/logs/honeypot.log") -> logging.Logger:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("ParamikoHoneypot")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(remote_ip)s:%(remote_port)s %(message)s"
    )
    handler.setFormatter(formatter)

    def add_default(record):
        if not hasattr(record, "remote_ip"):
            record.remote_ip = "-"
        if not hasattr(record, "remote_port"):
            record.remote_port = "-"
        return True

    handler.addFilter(add_default)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_connection_start(logger, addr):
    extra = {"remote_ip": addr[0], "remote_port": addr[1]}
    logger.info("connection_start", extra=extra)


def log_connection_end(logger, addr, duration):
    extra = {"remote_ip": addr[0], "remote_port": addr[1]}
    logger.info(f"connection_end duration={duration:.2f}s", extra=extra)


def log_auth_attempt(logger, addr, username, password):
    extra = {"remote_ip": addr[0], "remote_port": addr[1]}
    logger.info(
        f"auth_attempt user={username!r} password={password!r}",
        extra=extra,
    )


def log_command(logger, addr, cmd):
    extra = {"remote_ip": addr[0], "remote_port": addr[1]}
    logger.info(f"command {cmd!r}", extra=extra)


def log_data(logger, addr, data):
    extra = {"remote_ip": addr[0], "remote_port": addr[1]}
    logger.info(f"data {data!r}", extra=extra)
