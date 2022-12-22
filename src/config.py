import configparser
import os
from pathlib import Path

SRC = Path(__file__).parent
PROJECT = SRC.parent
CONFIG_PATH = PROJECT / 'config.ini'

os.chdir(PROJECT)


def load_config(path=CONFIG_PATH):
    path = Path(path)
    if not path.is_file():
        print(f"No config file found at {path}")
        exit()

    CONFIG_PATH = path
    config = configparser.ConfigParser()
    config.read(path)
    return config

def todict(config):
    return {section: dict(config[section]) for section in config.sections()}