"""Bounded Tencent cc-connect rollout; all installer outputs stay in the component root."""
import argparse
import ast
import datetime
import fcntl
import hashlib
import io
import json
import os
import secrets
import shutil
import signal
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path('/workspace/cc-connect')
PACK_SHA = '7852f41aa27d59ce6e1012a0b9d47cc6633d98342d12169e29bf1c6081f98c41'
TAG = 'fork-v1.5.1-beta.1+notify.1'
PKG_SHA = '246d4528b4a3a850f5bf5982d6309beac25331879ed556f49b76608df8bc32d0'
ASSET = 'cc-connect-v1.5.1-beta.1+notify.1-linux-amd64.tar.gz'
BIN_MEMBER = 'cc-connect-v1.5.1-beta.1+notify.1-linux-amd64'
HELPERS = ('codex-recovery-watch.py', 'codex-upstream-watch.py', 'codex-restore-heartbeat.py',
           'rotate-codex-session.py', 'codex-stop-heartbeat.py', 'codex-new-session.py',
           'verify-cc-features.py')
MARKERS = HELPERS[:3]
OPENER = urllib.request.build_opener()


def checked(path):
    if not path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('installer output outside cc-connect')
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('symlink in installer output')
    return path


def fetch(urls, digest):
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'tencent-cc-rollout/1.0'})
            with OPENER.open(request, timeout=45) as response:
                data = response.read(100 * 1024 * 1024 + 1)
            if len(data) <= 100 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == digest:
                return data
        except (OSError, TimeoutError):
            pass
    raise ValueError('download failed or SHA256 mismatch')


def atomic(path, data, mode=0o600):
    checked(path)
    temp = checked(path.with_name(path.name + '.rollout-tmp-' + secrets.token_hex(6)))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def api(cfg, path, method='GET'):
    m = cfg['management']
    request = urllib.request.Request('http://127.0.0.1:' + str(m.get('port', 9820))
                                    + '/api/v1/' + path,
                                    headers={'Authorization': 'Bearer ' + m.get('token', '')},
                                    method=method, data=b'' if method == 'POST' else None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        return json.load(response)['data']


def processes():
    main, cron = [], []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name) == os.getpid():
            continue
        try:
            args = (p / 'cmdline').read_bytes().split(b'\0')
            exe = os.readlink(p / 'exe').removesuffix(' (deleted)')
        except OSError:
            continue
        if exe == str(ROOT / 'cc-connect'):
            main.append(int(p.name))
        elif any(str(ROOT / marker).encode() in args for marker in (*MARKERS, 'rotate-codex-session.py')):
            cron.append(int(p.name))
    return main, cron


def stop_main():
    for pid in processes()[0]:
        os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        if not processes()[0]:
            return
        time.sleep(1)
    raise ValueError('cc-connect did not terminate; not overwriting running state')


def start_main():
    # Reuse the existing launcher, but do not invoke start-all.sh and touch Clash/new-api.
    command = ('while [ ! -f .stop ]; do bash ./run.sh >> ./cc.log 2>&1; sleep 10; done')
    subprocess.Popen(['flock', '-n', str(ROOT / '.watchdog.lock'), 'bash', '-c', command],
                     cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, env=os.environ.copy())


def wait_api(cfg):
    for _ in range(60):
        try:
            if api(cfg, 'projects/codex/heartbeat/status'):
                return
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(1)
    raise ValueError('management API did not recover')


def label():
    tree = ast.parse((ROOT / MARKERS[1]).read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id == 'PROBE_LABEL'
                                                for n in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
            if isinstance(node.value, ast.BoolOp) and isinstance(node.value.values[-1], ast.Constant):
                value = node.value.values[-1].value
                if isinstance(value, str):
                    return value
    return '腾讯容器-codex'


def stable_jobs(raw):
    rows = raw if isinstance(raw, list) else raw['jobs']
    return [{key: value for key, value in row.items() if key not in ('last_run', 'last_error')}
            for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', choices=['cloudstudio-ops', 'cloudstudio-ops2'], required=True)
    parser.add_argument('--notify-release', action='store_true', help='Explicitly approved fork release')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if args.notify_release and os.uname().machine not in ('x86_64', 'amd64'):
        raise ValueError('approved release is linux-amd64; refusing another architecture')
    import tomllib
    assert Path.cwd().resolve() == ROOT.resolve(), 'run from /workspace/cc-connect'
    for name in ('config.toml', 'data/crons/jobs.json', 'data/heartbeat_state.json', '.stop',
                 'data/codex-recovery-cycle.json', '.cc-release', 'cc-connect', 'run.sh',
                 '.watchdog.lock', 'cc.log', '.cc-rollout-result.json', '.cache/cc-rollout.lock',
                 'data/codex-recovery-cycle.lock', *HELPERS):
        checked(ROOT / name)
    cfg = tomllib.loads((ROOT / 'config.toml').read_text(encoding='utf-8'))
    if (ROOT / '.stop').exists():
        raise ValueError('existing .stop is intentional; leave it unchanged')
    raw = json.loads((ROOT / 'data/crons/jobs.json').read_text(encoding='utf-8'))
    jobs = raw if isinstance(raw, list) else raw['jobs']
    found = {m: [j for j in jobs if j.get('project') == 'codex1' and m in j.get('exec', '')]
             for m in MARKERS}
    if len(jobs) != 15 or any(len(v) != 1 for v in found.values()):
        raise ValueError('expected 15 jobs and one codex1 job per self-heal marker')
    hearts = {n: api(cfg, 'projects/' + n + '/heartbeat/status')
              for n in ['codex'] + ['codex' + str(i) for i in range(1, 10)]}
    if any(not isinstance(d.get('paused'), bool) for d in hearts.values()):
        raise ValueError('heartbeat status unknown')
    if not hearts['codex'].get('enabled'):
        raise ValueError('probe heartbeat is not configured; refusing to guess its configuration')
    if processes()[1]:
        raise ValueError('cron helper currently running; retry in an idle maintenance window')
    cycle_path = ROOT / 'data/codex-recovery-cycle.json'
    cycle = json.loads(cycle_path.read_text(encoding='utf-8')) if cycle_path.exists() else None
    if cycle and cycle.get('phase') not in ('monitoring', 'probing'):
        raise ValueError('existing recovery handoff is incomplete; let it finish first')
    info = {'jobs': len(jobs), 'paused': [n for n, d in hearts.items() if d['paused']],
            'notify_release': args.notify_release, 'phase': cycle.get('phase') if cycle else 'legacy'}
    if args.dry_run:
        print(json.dumps(info))
        return 0
    cache = checked(ROOT / '.cache')
    cache.mkdir(exist_ok=True, mode=0o700)
    with checked(cache / 'cc-rollout.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage = checked(cache / ('cc-rollout-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S')))
        stage.mkdir(mode=0o700)
        with checked(ROOT / 'data/codex-recovery-cycle.lock').open('a') as cycle_lock:
            fcntl.flock(cycle_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return install(args, cfg, raw, jobs, found, hearts, cycle, stage, info)


def install(args, cfg, raw, jobs, found, hearts, cycle, stage, info):
    base = 'https://raw.githubusercontent.com/Eitan-S-23/' + args.repo + '/main/cc-features/20261025/'
    mirror = 'https://cdn.jsdelivr.net/gh/Eitan-S-23/' + args.repo + '@main/cc-features/20261025/'
    data = fetch([base + 'tencent-cc-features.zip', mirror + 'tencent-cc-features.zip'], PACK_SHA)
    bundle = zipfile.ZipFile(io.BytesIO(data))
    sums = dict(line.split('  ', 1)[::-1] for line in bundle.read('SHA256SUMS').decode().splitlines())
    for name, digest in sums.items():
        if hashlib.sha256(bundle.read(name)).hexdigest() != digest:
            raise ValueError('bundle member checksum mismatch')
    probe_label = label()
    for name in (*HELPERS, 'tests/test_recovery_loop.py'):
        body = bundle.read(name)
        old_label = b'os.environ.get("CC_PROBE_LABEL") or "' + '腾讯容器-codex'.encode() + b'"'
        new_label = ('os.environ.get("CC_PROBE_LABEL") or '
                     + json.dumps(probe_label, ensure_ascii=False)).encode()
        body = body.replace(old_label, new_label)
        target = checked(stage / name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', RECOVERY_SCRIPTS_DIR=str(stage),
               RECOVERY_TEST_TMPDIR=str(stage), TMPDIR=str(stage), TEMP=str(stage), TMP=str(stage))
    test = subprocess.run(['python3', '-B', str(stage / 'tests/test_recovery_loop.py')], cwd=ROOT,
                          env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    atomic(stage / 'tests.log', test.stdout)
    if test.returncode:
        raise ValueError('staged recovery tests failed')
    binary = None
    if args.notify_release:
        url = ('https://github.com/Eitan-S-23/cc-connect/releases/download/'
               + TAG.replace('+', '%2B') + '/' + ASSET.replace('+', '%2B'))
        package = fetch([url, 'https://ghfast.top/' + url], PKG_SHA)
        tar = tarfile.open(fileobj=io.BytesIO(package), mode='r:gz')
        member = tar.getmember(BIN_MEMBER)
        if not member.isfile() or member.size > 100 * 1024 * 1024:
            raise ValueError('release member is not a regular binary')
        binary = tar.extractfile(member).read()
        if b'/notify' not in binary:
            raise ValueError('release lacks /notify static feature')
        atomic(stage / 'cc-connect.new', binary, 0o755)
        version = subprocess.run([str(stage / 'cc-connect.new'), '--version'], cwd=ROOT, env=env,
                                 capture_output=True, check=True, timeout=15).stdout
        if TAG.removeprefix('fork-').encode() not in version:
            raise ValueError('release version does not match the approved tag')
    backup = checked(stage / 'backup')
    backup.mkdir(mode=0o700)
    if (ROOT / 'config.toml').exists():
        shutil.copy2(ROOT / 'config.toml', checked(backup / 'config.toml'))
        (backup / 'config.toml').chmod(0o600)
    names = [*HELPERS, 'cc-connect', '.cc-release', 'data/crons/jobs.json',
             'data/heartbeat_state.json', 'data/codex-recovery-cycle.json']
    original = {}
    for name in names:
        src = ROOT / name
        original[name] = src.exists()
        if src.exists():
            dst = checked(backup / name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            dst.chmod(0o600)
    if processes()[1] or (ROOT / '.stop').exists():
        raise ValueError('component became busy or intentionally stopped during staging')
    created_stop = False
    changed = False
    try:
        atomic(ROOT / '.stop', b'cc feature rollout\n')
        created_stop = True
        stop_main()
        time.sleep(12)
        if processes()[0] or processes()[1]:
            raise ValueError('component did not quiesce')
        current = json.loads((ROOT / 'data/crons/jobs.json').read_text(encoding='utf-8'))
        if stable_jobs(current) != stable_jobs(raw):
            raise ValueError('job table changed during preflight; retry without overwriting it')
        raw = current
        jobs = raw if isinstance(raw, list) else raw['jobs']
        found = {marker: [row for row in jobs if row.get('project') == 'codex1'
                         and marker in row.get('exec', '')] for marker in MARKERS}
        atomic(backup / 'data/crons/jobs.json', (ROOT / 'data/crons/jobs.json').read_bytes())
        if (ROOT / 'data/heartbeat_state.json').exists():
            atomic(backup / 'data/heartbeat_state.json', (ROOT / 'data/heartbeat_state.json').read_bytes())
        changed = True
        for name in HELPERS:
            atomic(ROOT / name, (stage / name).read_bytes(), 0o755)
        if binary is not None:
            atomic(ROOT / 'cc-connect', binary, 0o755)
            release = ('repo=Eitan-S-23/cc-connect\ntag=' + TAG + '\nasset_sha256=' + PKG_SHA
                       + '\nbinary_sha256=' + hashlib.sha256(binary).hexdigest() + '\n')
            atomic(ROOT / '.cc-release', release.encode())
        if not cycle:
            now = datetime.datetime.now(datetime.UTC).isoformat()
            paused = all(hearts['codex' + str(i)]['paused'] for i in range(1, 10))
            cycle = {'phase': 'monitoring', 'monitor_since': now} if paused else {
                'phase': 'probing', 'restore_since': now, 'reset_done': [], 'resumed': [], 'skipped': []}
            atomic(ROOT / 'data/codex-recovery-cycle.json', (json.dumps(cycle) + '\n').encode())
            for marker, matches in found.items():
                matches[0]['enabled'] = marker == (MARKERS[1] if paused else MARKERS[0])
        found[MARKERS[0]][0]['description'] = '心跳恢复正常后停止 codex1~9 心跳并重新武装上游监控'
        atomic(ROOT / 'data/crons/jobs.json', (json.dumps(raw, ensure_ascii=False, indent=2) + '\n').encode())
        (ROOT / '.stop').unlink()
        created_stop = False
        start_main()
        wait_api(cfg)
        probe_resumed = hearts['codex']['paused']
        if probe_resumed:
            api(cfg, 'projects/codex/heartbeat/resume', 'POST')
        probe = api(cfg, 'projects/codex/heartbeat/status')
        if probe.get('paused') or not probe.get('enabled'):
            raise ValueError('probe heartbeat did not resume')
        after = json.loads((ROOT / 'data/crons/jobs.json').read_text(encoding='utf-8'))
        rows = after if isinstance(after, list) else after['jobs']
        if len(rows) != 15 or len(processes()[0]) != 1:
            raise ValueError('post-rollout component validation failed')
        phase = json.loads((ROOT / 'data/codex-recovery-cycle.json').read_text(encoding='utf-8'))['phase']
        version = subprocess.check_output([str(ROOT / 'cc-connect'), '--version'],
                                          cwd=ROOT, text=True).strip()
        info.update({'ok': True, 'phase': phase, 'backup': str(backup), 'version': version,
                     'probe_resumed': probe_resumed,
                     'notify_interaction_verified': False})
        atomic(ROOT / '.cc-rollout-result.json', (json.dumps(info) + '\n').encode())
        print(json.dumps(info))
        return 0
    except Exception:
        if not (ROOT / '.stop').exists():
            atomic(ROOT / '.stop', b'cc feature rollback\n')
        stop_main()
        if changed:
            for name, existed in original.items():
                target = ROOT / name
                if existed:
                    mode = 0o755 if name == 'cc-connect' or name in HELPERS else 0o600
                    atomic(target, (backup / name).read_bytes(), mode)
                elif target.exists():
                    target.unlink()
        if created_stop or (ROOT / '.stop').exists():
            (ROOT / '.stop').unlink()
        start_main()
        raise


if __name__ == '__main__':
    raise SystemExit(main())
