#!/usr/bin/env python3
"""sweep.py — cold-start ART method trace for a list of APKs.

Reads apps20.list (idx \t package \t versionCode \t component \t url).
For each: fetch (if needed), install, then N cold-start captures.
A capture is: force-stop; am start-activity -S -W -P <file> -n <component>;
poll the on-device file until its size stops growing (ART flushes the trace
buffer when the app reports idle); pull.
"""
import json, os, subprocess, sys, time

DEV = 'adb'
OUT = '.'


def adb(*args, **kw):
    return subprocess.run([DEV] + list(args), capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, **kw).stdout


def devsize(path):
    o = adb('shell', 'stat', '-c', '%s', path)
    for tok in o.split():
        if tok.isdigit():
            return int(tok)
    return 0


def wait_stable(path, tries=20):
    prev, cur = -1, 0
    for _ in range(tries):
        cur = devsize(path)
        if cur == prev and cur > 100_000:
            return cur
        prev = cur
        time.sleep(1)
    return cur


def capture(pkg, comp, idx, rep):
    remote = f'/data/local/tmp/mine/x{idx}_r{rep}.trace'
    adb('shell', 'am', 'force-stop', pkg)
    adb('shell', 'rm', '-f', remote)
    o = adb('shell', f'am start-activity -S -W -P {remote} -n {comp}')
    sz = wait_stable(remote)
    if sz > 100_000:
        local = os.path.join(OUT, f'x{idx}_r{rep}.trace')
        subprocess.run([DEV, 'pull', remote, OUT], capture_output=True,
                       stdin=subprocess.DEVNULL)
        return sz, o
    return sz, o


def main():
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    os.makedirs('apks', exist_ok=True)
    rows = [l.rstrip('\n').split('\t') for l in open('apps20.list')]
    for idx, pkg, vc, comp, url in rows:
        apk = f'apks/{pkg}_{vc}.apk'
        if not os.path.exists(apk):
            subprocess.run(['curl', '-sSL', '--max-time', '180', '-o', apk, url],
                           stdin=subprocess.DEVNULL)
        subprocess.run([DEV, 'install', '-r', '-g', apk], capture_output=True,
                       stdin=subprocess.DEVNULL)
        got = []
        for r in range(1, reps + 1):
            sz, o = capture(pkg, comp, idx, r)
            state = 'ok' if 'Status: ok' in o else 'ERR:' + o.strip().splitlines()[-1][:40]
            got.append(f'r{r}={sz}({state})')
            time.sleep(1)
        print(f'{pkg:46s} {" ".join(got)}', flush=True)


if __name__ == '__main__':
    main()
