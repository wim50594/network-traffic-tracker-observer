import os
import json
import pandas as pd
from config import load_config
from utils.utility import init_logger
    
config = load_config()
logs = init_logger("Parser", config)

class DataParser:

    def __init__(self, path):
        self.path = path
        self.domains = sorted(os.listdir(path))
        self.call_paths = sorted(self._find_paths(path))

    def map(self, fn, filename='resources.json', debug=False):
        results = []
        for p in self.call_paths:
            p = os.path.join(p, filename)
            if not os.path.exists(p):
                if debug:
                    print(f"Not found: {p}")
                continue
            ext = os.path.splitext(filename)[1]
            if ext == '.txt':
                with open(p) as f:
                    file = f.read()
            elif ext == '.json':
                with open(p) as f:
                    file = json.load(f)
            else:
                raise ValueExeption(
                    "Only support txt and json files for map function")

            results.append(fn(file))
        return results

    def map_index(self, fn, df, filename='data.json', debug=False):
        indices = []
        results = []
        for p in self.call_paths:
            name = os.path.basename(os.path.dirname(p))
            if name not in df['context'].values:
                if debug:
                    print(f"Skip, no indices for: {name}")
                continue

            p = os.path.join(p, filename)

            if not os.path.exists(p):
                if debug:
                    print(f"Not found: {p}")
                continue

            ext = os.path.splitext(filename)[1]
            if ext == '.json':
                with open(p) as f:
                    resources = json.load(f)
            else:
                raise ValueExeption(
                    "Only support json files for map_index function")

            for idx, row in df[df['context'] == name].iterrows():
                indices.append(idx)
                results.append([fn(resources[idx - 1])
                               for idx in row['packets']])

        return pd.Series(results, index=indices)

    def _find_paths(self, path, hidden=False):
        return [cur_dir for parent_dir in self._list_dir(path) for cur_dir in self._list_dir(parent_dir)]

    def _list_dir(self, path, hidden=False):
        if hidden:
            # also list hidden files
            return [os.path.join(path, p) for p in os.listdir(path) if os.path.isdir(os.path.join(path, p))]
        else:
            return [os.path.join(path, p) for p in os.listdir(path) if os.path.isdir(os.path.join(path, p)) and not p.startswith('.')]