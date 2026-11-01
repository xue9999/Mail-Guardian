#!/usr/bin/python3
"""Run offline candidate syntax checks against currently installed images."""
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guardian_images as g
import image_discovery as d


def main():
    if os.geteuid() != 0: raise RuntimeError('root required')
    os.umask(0o077)
    pins = d.parse_compose(g.RUNTIME)
    rows = [{'repo': repo, 'upstream_version': pin['version'],
             'candidate': {'ref': pin['ref'], 'index_digest': pin['digest'],
                           'tag': pin['version'] + ('-alpine' if repo == 'redis' else '')}}
            for repo, pin in pins.items()]
    g.preflight(rows)
    print('Current pinned images passed isolated configuration checks.')


if __name__ == '__main__':
    main()
