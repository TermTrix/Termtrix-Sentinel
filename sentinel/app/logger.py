import structlog
from pathlib import Path
import os

def set_process_id(_, __, event_dict):
    event_dict["process_id"] = os.getpid()
    
    return event_dict


class StructLog:
    def __init__(self):
        self.configured = False
        self.logger = self.load_config()

    def load_config(self):
        if not self.configured:
            structlog.configure(
                processors=[
                    structlog.processors.add_log_level,
                    structlog.processors.TimeStamper(fmt="iso"),
                    set_process_id,
                    structlog.processors.JSONRenderer(),
                ],
                logger_factory=structlog.WriteLoggerFactory(
                    file=Path("/app/logs/app.log").open("a", encoding="utf-8")
                ),
            )
            self.configured = True

        return structlog.get_logger()

    def info(self, message):
        self.logger.info(message)

    def debug(self, message):
        self.logger.debug(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)
    
    def exception(self, message):
        self.logger.exception(message)


logger = StructLog()
