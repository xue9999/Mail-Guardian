#!/usr/bin/python3
"""Check current Redis can read a disposable export; never mount its volume."""
import importlib.machinery
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guardian_images as g
import image_discovery as d


def main():
    if os.geteuid() != 0: raise RuntimeError('root required')
    os.umask(0o077)
    ref = d.parse_compose(g.RUNTIME)['redis']['ref']
    helper = importlib.machinery.SourceFileLoader('guardian_helper_probe', str(g.HELPER)).load_module()
    model = helper.Dispatcher('pilot').dispatch('export-redis')
    g.check_redis_model(ref, model)
    print('Current Redis read an isolated live model export successfully.')


if __name__ == '__main__':
    main()
