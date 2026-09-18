#!/usr/bin/env python3
"""Finds what there is to gate on this server, and what already is.

    sudo tools/discover.py                 # report
    sudo tools/discover.py --apply HOST    # add the gate include to HOST's server block

Reads the running nginx configuration (`nginx -T`) and lists every server
block: its names, ports, and whether it includes xauth-gate.conf. Then lists
Docker containers publishing ports that no gated server block fronts.

--apply inserts `include /etc/nginx/xauth/xauth-gate.conf;` right after the
server_name line of that host's server block, keeps a .bak of the file, runs
`nginx -t`, and puts the original back if the test fails. It never touches a
block that is already gated, and never the auth site itself. Reloading nginx
and adding the host to ALLOWED_HOSTS are printed, not done.
"""
from __future__ import annotations

import json, os, re, shutil, subprocess, sys

GATE = "xauth-gate.conf"
SNIPPET = "/etc/nginx/xauth/xauth-gate.conf"


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None


def nginx_dump() -> str | None:
    r = run(["nginx", "-T"])
    if r is None:
        return None
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        return None
    return r.stdout


def server_blocks(dump: str):
    """Yields (file, block_text) for every server { } block, from nginx -T
    output, which prefixes each file with '# configuration file PATH:'."""
    current = None
    depth = 0
    buf = []
    start_depth = None
    for line in dump.splitlines():
        m = re.match(r"# configuration file (.+):$", line)
        if m:
            current = m.group(1)
            continue
        stripped = re.sub(r"#.*", "", line)
        if start_depth is None and re.match(r"\s*server\s*\{", stripped):
            start_depth = depth
            buf = []
        if start_depth is not None:
            buf.append(line)
        depth += stripped.count("{") - stripped.count("}")
        if start_depth is not None and depth == start_depth:
            yield current, "\n".join(buf)
            start_depth = None


def describe(block: str):
    names = []
    for m in re.finditer(r"^\s*server_name\s+([^;]+);", block, re.M):
        names += m.group(1).split()
    listens = [m.group(1).strip() for m in re.finditer(r"^\s*listen\s+([^;]+);", block, re.M)]
    return {
        "names": names or ["(default)"],
        "listen": listens,
        "gated": GATE in block,
        "is_auth_site": "xauth_web" in block and GATE not in block and "auth_request" not in block,
        "has_auth_request": "auth_request" in block,
        # A bare http -> https redirect; nothing to gate.
        "redirect_only": bool(re.search(r"return\s+30[178]", block)) and "proxy_pass" not in block and "root" not in block,
    }


def docker_published():
    r = run(["docker", "ps", "--format", "{{json .}}"])
    if r is None or r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        c = json.loads(line)
        ports = [p.strip() for p in c.get("Ports", "").split(",") if "->" in p]
        if ports:
            out.append({"name": c["Names"], "image": c["Image"], "ports": ports})
    return out


def report():
    dump = nginx_dump()
    servers = []
    if dump is None:
        print("nginx: not found or `nginx -T` failed (run with sudo?)")
    else:
        for file, block in server_blocks(dump):
            d = describe(block)
            d["file"] = file
            servers.append(d)

    print("\nnginx server blocks")
    print(f"  {'host':40} {'listen':22} status")
    for s in servers:
        if s["is_auth_site"]:
            status = "auth site (never gate this)"
        elif s["gated"]:
            status = "GATED"
        elif s["has_auth_request"]:
            status = "has its own auth_request -- check before gating"
        elif s["redirect_only"]:
            status = "redirect only"
        else:
            status = "not gated"
        print(f"  {', '.join(s['names'])[:40]:40} {', '.join(s['listen'])[:22]:22} {status}")
    if not servers:
        print("  (none)")

    fronted = {n for s in servers for n in s["names"]}
    print("\ndocker containers with published ports")
    conts = docker_published()
    for c in conts:
        print(f"  {c['name']:30} {c['image'][:30]:30} {', '.join(c['ports'])}")
    if not conts:
        print("  (none, or docker not available)")

    ungated = [s for s in servers if not s["gated"] and not s["is_auth_site"] and not s["redirect_only"]
               and s["names"] != ["(default)"]]
    if ungated:
        print("\nto gate a host:")
        for s in ungated:
            host = s["names"][0]
            print(f"  sudo tools/discover.py --apply {host}      # then add {host} to ALLOWED_HOSTS in deploy/xauth.env")
    if conts and not servers:
        print("\nThese containers have no nginx in front of them. The gate needs one: see nginx/README.md.")


def apply(host: str):
    dump = nginx_dump()
    if dump is None:
        sys.exit("nginx -T failed; run with sudo")
    target = None
    for file, block in server_blocks(dump):
        d = describe(block)
        if host in d["names"]:
            if d["gated"]:
                sys.exit(f"{host} is already gated")
            if d["is_auth_site"]:
                sys.exit(f"{host} looks like the xAuth login site itself; never gate it")
            target = (file, block, d)
            break
    if target is None:
        sys.exit(f"no server block with server_name {host}")
    file, block, d = target
    if not os.path.exists(SNIPPET):
        sys.exit(f"{SNIPPET} is missing; run deploy/setup.sh first (or copy nginx/xauth-gate.conf there)")

    with open(file) as f:
        text = f.read()
    # Find the server block in the real file by its server_name line, and
    # insert the include right after that line.
    pattern = re.compile(r"(^[ \t]*server_name\s+[^;]*\b" + re.escape(host) + r"\b[^;]*;[ \t]*\n)", re.M)
    m = pattern.search(text)
    if not m:
        sys.exit(f"could not find the server_name line for {host} in {file}")
    indent = re.match(r"[ \t]*", m.group(1)).group(0)
    new = text[:m.end()] + f"{indent}include {SNIPPET};\n" + text[m.end():]

    shutil.copy2(file, file + ".bak")
    with open(file, "w") as f:
        f.write(new)
    r = run(["nginx", "-t"])
    if r is None or r.returncode != 0:
        shutil.copy2(file + ".bak", file)
        sys.exit(f"nginx -t failed; {file} restored:\n{(r.stderr if r else '')}")
    print(f"added the gate to {host} in {file} (backup: {file}.bak)")
    print(f"now: add {host} to ALLOWED_HOSTS in deploy/xauth.env, restart auth-web, then `sudo nginx -s reload`")
    print("if the app has non-browser clients (mobile app, API), read docs/integrations.md first")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--apply"] and len(args) == 2:
        apply(args[1])
    elif not args:
        report()
    else:
        sys.exit(__doc__)
