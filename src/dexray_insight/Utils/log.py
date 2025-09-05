#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""Logging utilities for Dexray Insight.

This module provides custom logging configuration with colored console output,
file logging capabilities, and APK-specific debug logging functionality.
"""

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

import logging
from pathlib import Path
from typing import Optional


class NullHandler(logging.Handler):
    """Null logging handler that discards log records."""

    def emit(self, record):
        """Discard the log record."""


class CustomFormatter(logging.Formatter):
    """Custom logging formatter to add colors and custom prefixes, with dynamic format based on log level."""

    # Define prefix, color, and format for each log level
    FORMAT = {
        logging.DEBUG: "\033[96m[DEBUG] %(filename)s : %(message)s\033[0m",  # Cyan for DEBUG, including file name
        logging.INFO: "\033[92m[+] %(message)s\033[0m",  # Green for INFO
        logging.WARNING: "\033[93m[W] %(message)s\033[0m",  # Orange for WARNING
        logging.ERROR: "\033[91m[-] %(message)s\033[0m",  # Red for ERROR
    }

    def format(self, record):
        """Format log record with color based on level."""
        self._style._fmt = self.FORMAT.get(record.levelno, self.FORMAT[logging.ERROR])  # Default to ERROR format
        return logging.Formatter.format(self, record)


class LogFilter(logging.Filter):
    """Filter log records by filename."""

    def __init__(self, files_to_filter):
        """Initialize filter with files to include."""
        self.files = files_to_filter

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log record based on filename."""
        if record.filename in self.files:
            return True
        return False


class FileFormatter(logging.Formatter):
    """Custom file formatter without color codes for file output."""

    # Define format for each log level without color codes
    FORMAT = {
        logging.DEBUG: "[DEBUG] %(asctime)s - %(filename)s : %(message)s",
        logging.INFO: "[+] %(asctime)s - %(message)s",
        logging.WARNING: "[W] %(asctime)s - %(message)s",
        logging.ERROR: "[-] %(asctime)s - %(message)s",
    }

    def format(self, record):
        """Format log record without colors for file output."""
        self._style._fmt = self.FORMAT.get(record.levelno, self.FORMAT[logging.ERROR])
        return logging.Formatter.format(self, record)


def set_logger(args, config=None):
    """Configure logging based on command line arguments and config."""
    log_level = logging.ERROR  # Default to ERROR
    if args.debug == "INFO":
        log_level = logging.INFO
    elif args.debug == "WARNING":
        log_level = logging.WARNING
    elif args.debug == "DEBUG":
        log_level = logging.DEBUG
    else:
        log_level = logging.ERROR

    logger = logging.getLogger()
    logger.setLevel(log_level)

    logging.getLogger("androguard").addHandler(NullHandler())
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    if args.filter is not None:
        log_filter = LogFilter(args.filter)
        logger.addFilter(log_filter)

    # Remove all handlers associated with the logger object.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create a console handler with the custom formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    logger.addHandler(console_handler)

    # Add file handler for debug logging if DEBUG level is enabled
    if log_level == logging.DEBUG:
        file_handler = _create_debug_file_handler(args, config)
        if file_handler:
            logger.addHandler(file_handler)


def _create_debug_file_handler(args, config=None) -> Optional[logging.FileHandler]:
    """
    Create a file handler for debug logging based on temporal_analysis configuration.

    Args:
        args: Command line arguments
        config: Configuration object (optional)

    Returns:
        FileHandler instance or None if file logging should be disabled
    """
    try:
        # Determine log file location based on temporal_analysis configuration
        log_file_path = _get_debug_log_file_path(config)

        if log_file_path is None:
            return None

        # Ensure parent directory exists
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Create file handler
        file_handler = logging.FileHandler(log_file_path, mode="w", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileFormatter())

        print(f"[*] Debug logs will be written to: {log_file_path}")
        return file_handler

    except Exception as e:
        print(f"[W] Could not create debug log file: {e}")
        return None


def _get_debug_log_file_path(config=None) -> Optional[Path]:
    """
    Determine the debug log file path based on configuration.

    Args:
        config: Configuration object (optional)

    Returns:
        Path object for the debug log file or None
    """
    try:
        from datetime import datetime

        # Generate timestamp for log file name
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = f"dexray_debug_{timestamp}.log"

        # If no config provided, write to current directory
        if config is None:
            return Path.cwd() / log_filename

        # Get temporal analysis configuration
        temporal_config = config.get_temporal_analysis_config()

        # If temporal analysis is disabled, write to current directory
        if not temporal_config.get("enabled", True):
            return Path.cwd() / log_filename

        # If temporal analysis is enabled but we don't have the APK-specific directory yet,
        # write to the base temporal directory
        base_dir = temporal_config.get("base_directory", "./temp_analysis")
        base_path = Path(base_dir)

        # Create a general logs directory in the base temporal directory
        logs_dir = base_path / "logs"
        return logs_dir / log_filename

    except Exception as e:
        # Fallback to current directory
        print(f"[W] Error determining log file path, using current directory: {e}")
        return Path.cwd() / f"dexray_debug_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"


def setup_apk_specific_debug_logging(apk_name: str, temporal_paths=None) -> bool:
    """
    Update debug logging to use APK-specific log file in temporal directory.

    This should be called after the temporal directory structure is created
    to move debug logging to the APK-specific logs folder.

    Args:
        apk_name: Name of the APK being analyzed
        temporal_paths: TemporalDirectoryPaths object (optional)

    Returns:
        True if logging was updated successfully, False otherwise
    """
    try:
        from datetime import datetime

        logger = logging.getLogger()

        # Only proceed if we're in DEBUG level
        if logger.level != logging.DEBUG:
            return True

        # Find existing file handlers
        file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]

        if not file_handlers:
            return True  # No file handlers to update

        # Determine new log file path
        if temporal_paths and hasattr(temporal_paths, "logs_dir"):
            # Use the temporal directory logs folder
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            new_log_path = temporal_paths.logs_dir / f"dexray_{apk_name}_debug_{timestamp}.log"
        else:
            # Fallback to current directory
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            new_log_path = Path.cwd() / f"dexray_{apk_name}_debug_{timestamp}.log"

        # Ensure directory exists
        new_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove old file handlers and add new one
        for handler in file_handlers:
            logger.removeHandler(handler)
            handler.close()

        # Create new file handler
        new_file_handler = logging.FileHandler(new_log_path, mode="w", encoding="utf-8")
        new_file_handler.setLevel(logging.DEBUG)
        new_file_handler.setFormatter(FileFormatter())
        logger.addHandler(new_file_handler)

        print(f"[*] Debug logging updated to: {new_log_path}")
        return True

    except Exception as e:
        print(f"[W] Could not update debug logging: {e}")
        return False
