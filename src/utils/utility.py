import json
import os
import hashlib
import shutil
import logging
from pathlib import Path
from datetime import datetime
from difflib import SequenceMatcher


def write_json(obj, path):
    with open(path, 'w') as f:
        json.dump(obj, f, indent=4)


def str_sim(a, b):
    return SequenceMatcher(None, a, b).ratio()


def load_json(path):
    if not os.path.isfile(path):
        return None
    with open(path, 'r', errors='replace') as f:
        return json.load(f)


def read_dict(s):
    if not isinstance(s, str):
        return s
    return json.loads(s.replace("'", '"'))


def load_linesperated_textfile(path):
    if not path:
        return None

    with open(path) as f:
        return [line for line in f.read().splitlines() if not line.startswith("#") and not line == ""]


def md5(input: str):
    return hashlib.md5(input.encode('utf-8')).hexdigest()


def sha3(input: str):
    return hashlib.sha3_224(input.encode('utf-8')).hexdigest()


def create_folder(dir_path):
    Path(dir_path).mkdir(parents=True, exist_ok=True)


def rm_folder(dir_path):
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)


def write_file(filename, text):
    filename = Path(filename)
    create_folder(filename.parent)
    with open(filename, 'w') as f:
        f.write(text + '\n')


def append_file(filename, text):
    with open(filename, 'a') as f:
        f.write(text + '\n')


def list_files(path, hidden=False):
    if not os.path.isdir(path):
        create_folder(path)

    if hidden:
        # also list hidden files
        return [os.path.join(path, p) for p in os.listdir(path) if os.path.isfile(os.path.join(path, p))]
    else:
        return [os.path.join(path, p) for p in os.listdir(path) if os.path.isfile(os.path.join(path, p)) and not p.startswith('.')]


def list_dir(path, hidden=False):
    if not os.path.isdir(path):
        create_folder(path)

    if hidden:
        # also list hidden files
        return [os.path.join(path, p) for p in os.listdir(path) if os.path.isdir(os.path.join(path, p))]
    else:
        return [os.path.join(path, p) for p in os.listdir(path) if os.path.isdir(os.path.join(path, p)) and not p.startswith('.')]


def init_logger(name, config, verbose=False):
    logs = logging.getLogger(name)
    log_level = logging.getLevelName(config['logging']['level'])
    logs.setLevel(log_level)
    formatter = logging.Formatter(
        '[%(name)s / %(levelname)s] %(asctime)s: %(message)s', '%d.%m.%Y %H:%M:%S')

    filename = Path(config['logging'].get('directory', 'logs')) / \
        f"{name}-{datetime.today().strftime('%Y-%m-%d')}.log"
    create_folder(filename.parent)
    file_stream = logging.FileHandler(filename)
    file_stream.setLevel(log_level)
    file_stream.setFormatter(formatter)
    logs.addHandler(file_stream)

    if not verbose:
        console_stream = logging.StreamHandler()
        console_stream.setLevel(log_level)
        console_stream.setFormatter(formatter)
        logs.addHandler(console_stream)

    return logs


def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""

    # from whichcraft import which
    from shutil import which

    return which(name) is not None
