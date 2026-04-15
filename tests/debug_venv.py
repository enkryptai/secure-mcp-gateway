import os

command = '/tmp/sandbox-venv/bin/python'
real = os.path.realpath(command)
print(f'Command: {command}')
print(f'Real path: {real}')

# Test with realpath (what _detect_venv does)
parts = real.replace('\\', '/').split('/')
print(f'Realpath parts: {parts}')
for i, part in enumerate(parts):
    if part in ('bin', 'Scripts') and i >= 1:
        candidate = '/'.join(parts[:i])
        pyvenv = os.path.join(candidate, 'pyvenv.cfg')
        print(f'  Candidate: {candidate}, pyvenv.cfg exists: {os.path.isfile(pyvenv)}')

# Test with original path (not resolved)
parts2 = command.replace('\\', '/').split('/')
print(f'\nOriginal parts: {parts2}')
for i, part in enumerate(parts2):
    if part in ('bin', 'Scripts') and i >= 1:
        candidate = '/'.join(parts2[:i])
        pyvenv = os.path.join(candidate, 'pyvenv.cfg')
        print(f'  Candidate: {candidate}, pyvenv.cfg exists: {os.path.isfile(pyvenv)}')
