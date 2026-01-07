"""
XDG configuration path utilities for CloakPrompt.

Follows the XDG Base Directory Specification:
- https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
"""
import os
from pathlib import Path
from typing import Optional


class XDGConfig:
    """Handle XDG configuration paths for CloakPrompt."""

    APP_NAME = "cloakprompt-cli"
    CONFIG_FILENAME = "config.yaml"

    @classmethod
    def get_config_home(cls) -> Path:
        """
        Get the XDG configuration home directory.

        Returns:
            Path to XDG config home directory
        """
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config_home:
            return Path(xdg_config_home)

        # Default fallback: ~/.config
        return Path.home() / ".config"

    @classmethod
    def get_config_dirs(cls) -> list[Path]:
        """
        Get all XDG configuration directories in order of precedence.

        Returns:
            List of config directories in precedence order
        """
        config_home = cls.get_config_home()
        xdg_config_dirs = os.environ.get("XDG_CONFIG_DIRS", "/etc/xdg")

        config_dirs = [config_home]
        config_dirs.extend([Path(path) for path in xdg_config_dirs.split(":")])

        return config_dirs

    @classmethod
    def get_app_config_path(cls, config_filename: Optional[str] = None) -> Optional[Path]:
        """
        Get the application's configuration file path if it exists.

        Args:
            config_filename: Optional custom config filename

        Returns:
            Path to config file if found, None otherwise
        """
        filename = config_filename or cls.CONFIG_FILENAME

        for config_dir in cls.get_config_dirs():
            config_path = config_dir / cls.APP_NAME / filename
            if config_path.exists():
                return config_path

        return None

    @classmethod
    def get_default_config_path(cls, config_filename: Optional[str] = None) -> Path:
        """
        Get the default configuration file path (for writing new configs).

        Args:
            config_filename: Optional custom config filename

        Returns:
            Path to default config file location
        """
        config_home = cls.get_config_home()
        filename = config_filename or cls.CONFIG_FILENAME
        return config_home / cls.APP_NAME / filename

    @classmethod
    def ensure_config_dir_exists(cls) -> Path:
        """
        Ensure the application's config directory exists.

        Returns:
            Path to the application's config directory
        """
        config_dir = cls.get_default_config_path().parent
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir

    @classmethod
    def find_config_file(cls, filename: Optional[str] = None) -> Optional[Path]:
        """
        Find a configuration file in XDG directories.

        Args:
            filename: Config filename to search for

        Returns:
            Path to config file if found, None otherwise
        """
        filename = filename or cls.CONFIG_FILENAME

        # First check current directory
        current_dir_path = Path.cwd() / filename
        if current_dir_path.exists():
            return current_dir_path

        # Then check XDG directories
        return cls.get_app_config_path(filename)