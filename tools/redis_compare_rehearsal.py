#!/usr/bin/env python3
"""Synthetic-only two-Redis comparison rehearsal; never accepts real model data.

Run as an administrator on a disposable test host with a prebuilt, verified
Go test binary. Creates unique, labelled containers on an internal network,
without host ports or Docker volumes. Removes only resources created by this
invocation; a SIGKILL or host failure may require manual label-scoped cleanup.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import time

IMAGE = 'redis:7.4.9-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99'
DOCKER = '/usr/bin/docker'


def run(args, *, data=None, timeout=60):
    result = subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('Docker fixture operation failed')
    return result.stdout


def resp(commands):
    out = bytearray()
    for command in commands:
        out.extend(b'*%d\r\n' % len(command))
        for part in command:
            if isinstance(part, str):
                part = part.encode('ascii')
            out.extend(b'$%d\r\n' % len(part))
            out.extend(part)
            out.extend(b'\r\n')
    return bytes(out)


def inject(container, commands):
    result = run(['exec', '-i', container, 'redis-cli', '--pipe'], data=resp(commands), timeout=20)
    if b'errors: 0' not in result.lower():
        raise RuntimeError('synthetic Redis input rejected')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--test-binary', required=True, type=Path)
    p.add_argument('--sha256', required=True)
    args = p.parse_args()
    path = args.test_binary
    if os.geteuid() != 0 or not path.is_absolute() or len(args.sha256) != 64:
        raise RuntimeError('test binary must be a verified regular absolute path')
    for entry in [path, *path.parents]:
        info = entry.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise RuntimeError('test binary path must be root-owned and protected')
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_mode & 0o005 != 0o005:
        raise RuntimeError('test binary must be readable and executable by the runner')
    if hashlib.sha256(path.read_bytes()).hexdigest() != args.sha256:
        raise RuntimeError('test binary hash mismatch')
    image_id = run(['image', 'inspect', '--format', '{{.Id}}', IMAGE]).decode('ascii').strip()
    if not image_id.startswith('sha256:'):
        raise RuntimeError('pinned test image unavailable')
    token = secrets.token_hex(8)
    label = 'guardian.compare-fixture=' + token
    network = 'guardian-compare-' + token
    names = [network + '-a', network + '-b']
    created = []
    network_id = None
    try:
        network_id = run(['network', 'create', '--internal', '--label', label, network]).decode('ascii').strip()
        for name, alias in zip(names, ['a', 'b']):
            cid = run(['run', '-d', '--name', name, '--label', label, '--network', network,
                       '--network-alias', alias, '--memory', '256m', '--pids-limit', '96', IMAGE,
                       'redis-server', '--save', '', '--appendonly', 'no', '--bind', '0.0.0.0',
                       '--protected-mode', 'no', '--maxmemory-policy', 'noeviction']).decode('ascii').strip()
            created.append(cid)
        for cid in created:
            for _ in range(50):
                ping = subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'exec', cid, 'redis-cli', 'ping'],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False)
                if ping.returncode == 0 and ping.stdout.strip() == b'PONG':
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('synthetic Redis did not become ready')
        until = str(int(time.time()*1000)+20*60*1000)
        seed = [
            ['SELECT', '0'], ['SET', b'k\x00\n', b'v\x00\xff'],
            ['RPUSH', 'list', b'a\x00', b'b\xff'], ['SADD', 'set', b'a\x00', b'b\xff'],
            ['HSET', 'hash', b'f\x00', b'value\xff', 'plain', 'v', 'expfield', 'v'],
            ['ZADD', 'zset', '1.5', b'm\x00', '-inf', b'n\xff'],
            ['PEXPIREAT', b'k\x00\n', until], ['HPEXPIREAT', 'hash', until, 'FIELDS', '1', 'expfield'],
            ['SELECT', '1'], ['SET', b'db1\x00', b'v\xff'],
        ]
        for cid in created:
            inject(cid, seed)
            expiry = run(['exec', cid, 'redis-cli', '--raw', 'HPEXPIRETIME', 'hash', 'FIELDS', '1', 'expfield']).strip()
            if expiry != until.encode('ascii'):
                raise RuntimeError('synthetic field expiry was not set')
        def compare(mode):
            out = run(['run', '--rm', '--name', network + '-runner', '--label', label, '--network', network,
                       '--user', '65534:65534', '--read-only', '--mount', 'type=bind,src='+str(path)+',dst=/test,readonly',
                       '-e', 'GUARDIAN_TEST_REDIS_A=a:6379', '-e', 'GUARDIAN_TEST_REDIS_B=b:6379',
                       '-e', 'GUARDIAN_TEST_REDIS_MODE='+mode, '-e', 'GUARDIAN_TEST_REDIS_DEADLINE='+until,
                       IMAGE, '/test', '-test.run=^TestRedisIntegrationFixture$', '-test.v'], timeout=90)
            if b'--- PASS: TestRedisIntegrationFixture' not in out:
                raise RuntimeError('synthetic comparison did not pass')
            print('PASS ' + mode)
        compare('equal')
        inject(created[1], [['SELECT', '1'], ['SET', b'db1\x00', 'different']])
        compare('mismatch')
        inject(created[1], [['SELECT', '1'], ['SET', b'db1\x00', b'v\xff']])
        inject(created[1], [['SELECT', '0'], ['HPEXPIREAT', 'hash', str(int(until)+1000), 'FIELDS', '1', 'expfield']])
        compare('field-expiry')
        inject(created[1], [['SELECT', '0'], ['HPEXPIREAT', 'hash', until, 'FIELDS', '1', 'expfield'],
                            ['PEXPIREAT', b'k\x00\n', str(int(until)+1000)]])
        compare('key-expiry')
        inject(created[1], [['SELECT', '0'], ['PEXPIREAT', b'k\x00\n', until]])
        inject(created[1], [['SELECT', '0'], ['LPUSH', 'list', 'extra']])
        compare('list')
        inject(created[1], [['SELECT', '0'], ['LPOP', 'list'], ['SADD', 'set', 'extra']])
        compare('set')
        inject(created[1], [['SELECT', '0'], ['SREM', 'set', 'extra'], ['HSET', 'hash', 'plain', 'different']])
        compare('hash')
        inject(created[1], [['SELECT', '0'], ['HSET', 'hash', 'plain', 'v'], ['ZADD', 'zset', '2.5', b'm\x00']])
        compare('zset')
        inject(created[1], [['SELECT', '0'], ['ZADD', 'zset', '1.5', b'm\x00']])
        for cid in created:
            inject(cid, [['SELECT', '0'], ['XADD', 'stream', '*', 'f', 'v']])
        compare('unsupported')
    finally:
        # The client can time out after starting a --rm runner; inspect the
        # unique name as well as the tracked server IDs before removing it.
        labelled_containers = run(['ps', '-aq', '--filter', 'label=' + label]).decode('ascii').split()
        for cid in [network + '-runner', *reversed(created), *labelled_containers]:
            check = subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'inspect',
                                    '--format', '{{.Name}} {{index .Config.Labels "guardian.compare-fixture"}}', cid],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
            if check.returncode == 0 and check.stdout.decode('ascii').strip() in {
                    '/' + allowed + ' ' + token for allowed in [*names, network + '-runner']}:
                subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'rm', '-f', cid],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        labelled_networks = run(['network', 'ls', '-q', '--filter', 'label=' + label]).decode('ascii').split()
        for candidate in ([network_id] if network_id else []) + labelled_networks:
            check = subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'network', 'inspect',
                                    '--format', '{{.Name}} {{index .Labels "guardian.compare-fixture"}}', candidate],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
            if check.returncode == 0 and check.stdout.decode('ascii').strip() == network + ' ' + token:
                subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'network', 'rm', candidate],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        remaining_containers = run(['ps', '-aq', '--filter', 'label=' + label])
        remaining_networks = run(['network', 'ls', '-q', '--filter', 'label=' + label])
        if remaining_containers.strip() or remaining_networks.strip():
            raise RuntimeError('fixture cleanup incomplete; inspect label ' + label)
        print('Verified fixture resources removed for token ' + token)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        print('Synthetic Redis comparison rehearsal failed', file=sys.stderr)
        sys.exit(1)
