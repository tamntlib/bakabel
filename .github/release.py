"""Manual release checks. Credentials stay in environment/HTTP headers, never argv."""
import base64
import json
import os
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('registry redirect refused')


urlopen = build_opener(NoRedirect()).open


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def validate():
    for key, pattern in [('VERSION', r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'),
                         ('GITHUB_SHA', r'[a-f0-9]{40}'),
                         ('GITHUB_REPOSITORY', r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'),
                         ('CI_RUN_ID', r'[1-9][0-9]*'), ('ACCEPTANCE_RUN_ID', r'[1-9][0-9]*')]:
        demand(re.fullmatch(pattern, os.environ.get(key, '')), f'invalid {key}')


def gate():
    validate()
    repo, sha = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA']
    for workflow, run_id in [('ci', os.environ['CI_RUN_ID']),
                             ('acceptance', os.environ['ACCEPTANCE_RUN_ID'])]:
        endpoint = f'repos/{repo}/actions/runs/{run_id}'
        def api(path):
            return json.loads(subprocess.check_output(
                ['gh', 'api', '--hostname', 'github.com', path], text=True))
        run = api(endpoint)
        demand(run['head_sha'] == sha and run['path'] == f'.github/workflows/{workflow}.yaml'
               and run.get('event') == ('push' if workflow == 'ci' else 'workflow_dispatch')
               and run['status'] == 'completed' and run['conclusion'] == 'success',
               f'{workflow}: wrong source/workflow/event or unsuccessful run')
        report = api(endpoint + '/jobs?filter=latest&per_page=100')
        jobs = report['jobs']
        demand(jobs and len(jobs) == report['total_count'] and
               len({j['name'] for j in jobs}) == len(jobs) and
               all(j['status'] == 'completed' and j['conclusion'] == 'success' for j in jobs),
               f'{workflow}: missing, incomplete or unsuccessful jobs')
        if workflow == 'acceptance':
            demand(sorted(j['name'] for j in jobs) == sorted([
                'selection', 'acceptance (core-resources, all)',
                'acceptance (capacity, all)', 'acceptance (faults, all)']),
                'acceptance: exactly selection + three full all suites required')
        else:
            demand(any(j['name'] == 'test-and-build' for j in jobs), 'CI build job missing')


def registry(mode):
    validate()
    repo = os.environ['GITHUB_REPOSITORY'].lower()
    query = urlencode({'service': 'ghcr.io', 'scope': f'repository:{repo}:pull,push'})
    basic = base64.b64encode(f"{os.environ['GITHUB_ACTOR']}:{os.environ['GH_TOKEN']}".encode()).decode()
    with urlopen(Request('https://ghcr.io/token?' + query,
                         headers={'Authorization': 'Basic ' + basic}), timeout=30) as response:
        token = json.load(response)['token']
    digests = []
    for tag in (os.environ['VERSION'], 'sha-' + os.environ['GITHUB_SHA']):
        request = Request(f'https://ghcr.io/v2/{repo}/manifests/{tag}', method='HEAD', headers={
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, '
                      'application/vnd.docker.distribution.manifest.list.v2+json, '
                      'application/vnd.docker.distribution.manifest.v2+json'})
        try:
            with urlopen(request, timeout=30) as response:
                digest = response.headers.get('Docker-Content-Digest', '')
                demand(isinstance(digest, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', digest),
                       'missing or invalid registry digest')
                digests.append(digest)
        except HTTPError as error:
            if error.code != 404:
                raise
            digests.append(None)
    if mode == 'check':
        demand(digests == [None, None], 'version or SHA tag already exists; refusing overwrite')
    else:
        demand(digests[0] and digests[0] == digests[1], 'pushed tags missing or digest mismatch')
        return digests[0]


if __name__ == '__main__':
    try:
        demand(len(sys.argv) == 2 and sys.argv[1] in ('gate', 'check', 'verify'), 'invalid mode')
        result = gate() if sys.argv[1] == 'gate' else registry(sys.argv[1])
        if result:
            print(result)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError):
        raise SystemExit('Release check failed: verify inputs, run evidence and registry access; no overwrite allowed.')
