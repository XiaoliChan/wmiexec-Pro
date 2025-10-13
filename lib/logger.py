import sys
import logging

from rich.theme import Theme
from rich.console import Console
from rich.logging import RichHandler
from datetime import datetime


class FlushHandler(logging.StreamHandler):
    def emit(self, record):
        record_time = datetime.fromtimestamp(record.created).strftime("[%y/%m/%d %H:%M:%S]")
        level_name = record.levelname.ljust(8)
        msg = self.format(record)
        formatted_msg = f"\r{record_time} {level_name} {msg}"
        stream = self.stream
        stream.write(formatted_msg)
        stream.flush()

class Log:
    def __init__(self, log_level=logging.DEBUG):
        self.log_level = log_level
        self.wmi_console = Console(
            soft_wrap=True,
            tab_size=4,
            theme=Theme(
                {"logging.level.success": "green"}
            )
        )
        logging.basicConfig(
            format="%(message)s",
            datefmt="[%X]",
            handlers=[],
            encoding="utf-8"
        )
        logging.getLogger("impacket").disabled = True
        self.setup_logger1()
        self.setup_logger2()
    
    def setup_logger1(self):
        logger = logging.getLogger("wmiexec-pro")
        logging.addLevelName(100, "SUCCESS")
        logger.setLevel(self.log_level)
        logger.propagate = False
        if not logger.handlers:
            logger.addHandler(
                RichHandler(
                    console=self.wmi_console,
                    rich_tracebacks=True,
                    tracebacks_show_locals=False
                )
            )
    
    def setup_logger2(self):
        # Set up logging
        logger = logging.getLogger("CountdownLogger")
        logger.setLevel(self.log_level)
        logger.propagate = False
        # Use the custom handler
        if not logger.handlers:
            logger.addHandler(
                FlushHandler(sys.stdout)
            )