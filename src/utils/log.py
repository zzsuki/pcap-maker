import logging
from enum import Enum
from rich.logging import RichHandler


class LogLevelEnum(str, Enum):
    """日志级别枚举"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


default_level = logging.INFO


def get_logger(name, level=default_level):
    """Get logger with rich handler"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    FORMAT = "[%(asctime)s][%(levelname)s][%(filename)s][line %(lineno)s][%(funcName)5s()]: %(message)s"
    formatter = logging.Formatter(FORMAT)
    handler = RichHandler(show_time=False, show_level=False)
    # handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
