import json
import datetime
import logging
from logging.handlers import RotatingFileHandler

def setup_logger(log_file="scan_log.json"):
    """
    Sets up a logger with a rotating file handler.
    
    Parameters:
        log_file (str): The path to the log file.
        
    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("NmapLogger")
    logger.setLevel(logging.INFO)

    # Check if a handler is already attached to avoid duplicate logs
    if not logger.handlers:
        handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
        formatter = logging.Formatter('%(message)s')  # Simple formatter for JSON logs
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

def log_scan(target, port_range, options, result, log_file="scan_log.json"):
    """
    Logs scan details to a JSON file using a rotating file handler.
    
    Parameters:
        target (str): The target IP or domain.
        port_range (str): The range of ports scanned.
        options (dict): The options used for the scan.
        result (str): The scan result.
        log_file (str): The path to the log file.
    """
    logger = setup_logger(log_file)

    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "port_range": port_range,
        "options": options,
        "result": result
    }

    try:
        logger.info(json.dumps(log_entry))
    except Exception as e:
        print(f"Error logging scan details: {e}")
