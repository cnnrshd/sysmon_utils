"""sysmon_utils - Utilities for working with and testing Sysmon configs against Windows Event Logs"""
__author__ = "Connor Shade"

from rich.traceback import install as rich_log_install

rich_log_install(show_locals=False)
import logging

from commands.main_app import app as main_app
from config import config
from typer import Option

console = config.console


@main_app.callback()
def main_config(debug: bool = Option(False, help="Enable debugging")):
    config.debug = debug
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)


def main():
    main_app()


if __name__ == "__main__":
    main()
