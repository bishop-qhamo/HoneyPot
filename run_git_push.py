import subprocess
import pathlib

root = pathlib.Path(r'c:/Users/Murungi/OneDrive/My Projects')
cmds = [
    ['git', 'remote', '-v'],
    ['git', 'remote', 'set-url', 'origin', 'https://github.com/trey656/repo.git'],
    ['git', 'remote', '-v'],
    ['git', 'branch', '-M', 'main'],
    ['git', 'push', '-u', 'origin', 'main']
]

for cmd in cmds:
    p = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    print('>>>', ' '.join(cmd))
    print('returncode=', p.returncode)
    if p.stdout:
        print('STDOUT:\n' + p.stdout)
    if p.stderr:
        print('STDERR:\n' + p.stderr)
    print('---')
