"""Centralized logging configuration for the MCP OAuth application.

This module provides shared logging setup that ensures all logs are written to
both the console (when verbose) and to a configurable log file.
"""

import logging
import os
from pathlib import Path
from typing import Optional

# Global variable to store the configured log file path
# _file_handler_added: bool = False


def setup_file_logging(log_file_path: str) -> Optional[str]:
    """Set up file logging to specified path or default location.
    
    Args:
        log_file_path: Custom log file path, or None to use global setting
        
    Returns:
        Path to log file that was set up, or None if file logging disabled
    """
    log_file = Path(log_file_path)
    
    # Create parent directories if they don't exist
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Create the log file if it doesn't exist
    log_file.touch(exist_ok=True)
    
    # Test that we can write to it
    with open(log_file, 'a') as f:
        f.write("")  # Test write
        
    return str(log_file)

def configure_logger(logger_name: str, verbose: bool = True) -> logging.Logger:
    """Configure a logger with both console and file output.
    
    Args:
        logger_name: Name of the logger (usually __name__)
        verbose: Whether to enable console output
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s'
    )
    
    # Add file handler
    log_file_path = os.path.join("/tmp", f"{logger_name}.log")
    try:
        log_file = setup_file_logging(log_file_path)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            # Log the setup (but only once to avoid recursion)
            # global _file_handler_added
            # if not _file_handler_added:
            logger.info(f"Logging to file: {log_file}")
                # _file_handler_added = True
                
    except Exception as e:
        # If file logging fails, continue without it
        print(f"Warning: Could not set up file logging: {e}")
    
    # Add console handler if verbose
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger
