
import os
import time
import json

_file_cache = {}

def load_file_cached(path, loader_func, default=None):
    global _file_cache
    if path not in _file_cache:
        _file_cache[path] = {'data': default, 'mtime': 0}

    cache = _file_cache[path]
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return default

    if mtime != cache['mtime']:
        try:
            cache['data'] = loader_func(path)
            cache['mtime'] = mtime
        except Exception:
            # On error, keep old data or default?
            # If old data exists, maybe keep it. If not, default.
            if cache['data'] is None:
                cache['data'] = default
            # We don't update mtime so we retry next time
    return cache['data']

def _json_loader(path):
    with open(path, 'r') as f:
        return json.load(f)

def _list_loader(path):
    with open(path, 'r') as f:
        return set(line.strip() for line in f if line.strip() and not line.startswith('#'))
