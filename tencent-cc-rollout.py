"""Temporary, fixed-purpose cc-connect deployment hook. No generic remote execution."""
import hashlib
import json
import os
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path('/workspace/cc-connect')
TASK = 'CC_ROLLOUT_20261025'
RUNNER_SHA = '30cf7ca6fa94b7d22c3d383a98ad78bd116cd7c237690385db1a829573d8bab1'


def checked(path):
    if not path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('bootstrap output outside cc-connect')
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('symlink in bootstrap output')
    return path


def atomic(path, data):
    checked(path)
    temp = checked(path.with_name(path.name + '.tmp-' + secrets.token_hex(6)))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def fetch(repo, name):
    urls = ['https://raw.githubusercontent.com/Eitan-S-23/' + repo + '/main/cc-features/20261025/' + name,
            'https://cdn.jsdelivr.net/gh/Eitan-S-23/' + repo + '@main/cc-features/20261025/' + name]
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'tencent-cc-bootstrap/1.0'})
            with urllib.request.urlopen(request, timeout=25) as response:
                return response.read(2 * 1024 * 1024)
        except OSError:
            pass
    raise ValueError('bootstrap asset download failed')


def post(path, payload, token=None):
    headers = {'Content-Type': 'application/json', 'User-Agent': 'tencent-cc-bootstrap/1.0'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request('https://open.feishu.cn/open-apis/' + path,
                                    data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def report(cfg, space, phase, data):
    token = post('auth/v3/tenant_access_token/internal', {
        'app_id': cfg['app_id'], 'app_secret': cfg['app_secret']})['tenant_access_token']
    payload = {'task': TASK, 'space': space, 'phase': phase, 'data': data}
    text = TASK + ' ' + json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    result = post('im/v1/messages?receive_id_type=open_id', {
        'receive_id': cfg['owner_open_id'], 'msg_type': 'text',
        'content': json.dumps({'text': text}, ensure_ascii=False)}, token)
    if result.get('code') != 0:
        raise ValueError('deployment receipt failed')


def snapshot():
    import platform
    import tomllib
    cfg = tomllib.loads((ROOT / 'config.toml').read_text(encoding='utf-8'))
    raw = json.loads((ROOT / 'data/crons/jobs.json').read_text(encoding='utf-8'))
    jobs = raw if isinstance(raw, list) else raw['jobs']
    m = cfg['management']
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    hearts = {}
    for name in ['codex'] + ['codex' + str(i) for i in range(1, 10)]:
        request = urllib.request.Request('http://127.0.0.1:' + str(m.get('port', 9820))
                                        + '/api/v1/projects/' + name + '/heartbeat/status',
                                        headers={'Authorization': 'Bearer ' + m.get('token', '')})
        try:
            with opener.open(request, timeout=5) as response:
                d = json.load(response)['data']
            hearts[name] = {key: d.get(key) for key in ('enabled', 'paused', 'interval_mins')}
        except OSError:
            hearts[name] = {'status': 'unknown'}
    version = subprocess.check_output([str(ROOT / 'cc-connect'), '--version'], cwd=ROOT, text=True).strip()
    cycle = ROOT / 'data/codex-recovery-cycle.json'
    return {'version': version, 'arch': platform.machine(), 'jobs': len(jobs),
            'projects': len(cfg['projects']), 'hearts': hearts,
            'cycle': json.loads(cycle.read_text(encoding='utf-8')).get('phase') if cycle.exists() else None,
            'notify_marker': b'/notify' in (ROOT / 'cc-connect').read_bytes(),
            'selfheal': [{key: job.get(key) for key in ('id', 'enabled')} for job in jobs
                        if any(name in job.get('exec', '') for name in (
                            'codex-recovery-watch.py', 'codex-upstream-watch.py',
                            'codex-restore-heartbeat.py'))]}


def worker(app_dir, cfg, repo, space, app_hash):
    try:
        if hashlib.sha256(cfg['app_id'].encode()).hexdigest() != app_hash:
            raise ValueError('wrong butler App for this container')
        marker = Path('/workspace/run-new-api.sh' if space == 'icgsqq' else '/workspace/run-bots.sh')
        if not marker.is_file():
            raise ValueError('wrong container startup marker')
        stage = checked(ROOT / '.cache/cc-rollout-bootstrap')
        stage.mkdir(parents=True, exist_ok=True, mode=0o700)
        done = checked(stage / 'done.json')
        if done.exists():
            return
        before = snapshot()
        atomic(stage / 'before.json', (json.dumps(before) + '\n').encode())
        report(cfg, space, 'preflight', before)
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            try:
                control = json.loads(fetch(repo, 'control.json'))
            except (OSError, ValueError):
                time.sleep(15)
                continue
            if control.get('task') != TASK or control.get('operation') != 'install':
                time.sleep(15)
                continue
            body = fetch(repo, 'rollout.py')
            if hashlib.sha256(body).hexdigest() != RUNNER_SHA:
                raise ValueError('deployment runner SHA256 mismatch')
            runner = checked(stage / 'rollout.py')
            atomic(runner, body)
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(stage),
                       TEMP=str(stage), TMP=str(stage))
            report(cfg, space, 'installing', {'release': 'fork-v1.5.1-beta.1+notify.1'})
            result = subprocess.run(['python3', '-B', str(runner), '--repo', repo, '--notify-release'],
                                    cwd=ROOT, env=env, capture_output=True)
            output = result.stdout + result.stderr
            atomic(stage / 'install.log', output)
            if result.returncode != 0:
                reason = result.stderr.decode('utf-8', 'replace').splitlines()[-1:]
                text = ''.join(reason).replace(cfg['app_secret'], '[redacted]')[:400]
                report(cfg, space, 'failed', {'reason': text, 'returncode': result.returncode})
                return
            status = json.loads((ROOT / '.cc-rollout-result.json').read_text(encoding='utf-8'))
            status['live'] = snapshot()
            atomic(done, (json.dumps(status) + '\n').encode())
            report(cfg, space, 'installed', status)
            return
        report(cfg, space, 'waiting_expired', {'changed_cc_connect': False})
    except Exception as exc:
        try:
            report(cfg, space, 'bootstrap_failed', {'reason': type(exc).__name__ + ': ' + str(exc)[:300]})
        except Exception:
            print('cc-connect bootstrap failed; butler remains available', flush=True)


def start_rollout(app_dir, cfg, repo, space, app_hash):
    if repo not in ('cloudstudio-ops', 'cloudstudio-ops2') or space not in ('icgsqq', 'aijjny'):
        raise ValueError('unknown deployment target')
    threading.Thread(target=worker, args=(app_dir, cfg, repo, space, app_hash),
                     name='cc-feature-rollout', daemon=True).start()
