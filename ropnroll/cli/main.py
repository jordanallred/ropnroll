from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .. import libcdb
from ..core import loader, output, scanner, security
from ..core.gadget import Terminator
from ..solve import callchain, chain as chainmod, jop, onegadget, pivot, srop, syscallchain
from ..solve.pool import GadgetPool
from ..semantics import query as querymod
from ..verify.emulate import verify_chain

console = Console()


def _load_pool(paths: list[str], scan_opts: scanner.ScanOptions) -> tuple[GadgetPool, list]:
    pool = GadgetPool()
    images = []
    for p in paths:
        img = loader.load(p)
        gs = scanner.scan_image(img, scan_opts)
        pool.add(img, gs)
        images.append(img)
    return pool, images


def _scan_opts(args) -> scanner.ScanOptions:
    bad = bytes.fromhex(args.bad_bytes) if getattr(args, "bad_bytes", None) else b""
    return scanner.ScanOptions(
        max_insns=args.max_insns, rop=not args.no_rop, jop=not args.no_jop,
        sys=not args.no_sys, bad_bytes=bad,
    )


def cmd_scan(args):
    pool, images = _load_pool([args.binary], _scan_opts(args))
    gadgets = pool.all()
    if args.regex:
        import re
        rx = re.compile(args.regex)
        gadgets = [g for g in gadgets if rx.search(g.text)]
    gadgets.sort(key=lambda g: g.address)
    if args.out:
        with open(args.out, "w") as f:
            for g in gadgets:
                f.write(f"0x{g.address:016x} : {g.text}\n")
        console.print(f"[green]wrote {len(gadgets)} gadgets to {args.out}[/green]")
        return
    for g in gadgets[: args.limit]:
        console.print(f"0x{g.address:016x} : {escape(g.text)}")
    console.print(f"[bold]{len(gadgets)}[/bold] gadgets total"
                   + (f" (showing first {args.limit})" if len(gadgets) > args.limit else ""))


def cmd_security(args):
    img = loader.load(args.binary)
    opts = _scan_opts(args)
    gs = scanner.scan_image(img, opts)
    report = security.build_report(img, gs)
    t = Table(title=f"security report: {args.binary}")
    t.add_column("property")
    t.add_column("value")
    for k, v in report.lines:
        t.add_row(k, v)
    console.print(t)


def cmd_search(args):
    pool, images = _load_pool(args.binary, _scan_opts(args))
    try:
        results = querymod.search(pool, args.query, limit=args.limit)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if not results:
        console.print("[yellow]no gadgets matched[/yellow]")
        return
    for g, eff, field in results:
        console.print(f"0x{g.address:016x} : {escape(g.text)}  [dim]sp_delta={eff.sp_delta}[/dim]")


def cmd_pivot(args):
    pool, images = _load_pool(args.binary, _scan_opts(args))
    pivots = pivot.find_pivots(pool)
    t = Table(title="stack pivots")
    t.add_column("address")
    t.add_column("gadget")
    t.add_column("kind")
    for p in pivots[: args.limit]:
        t.add_row(f"0x{p.gadget.address:x}", escape(p.gadget.text), p.kind)
    console.print(t)


def cmd_jop(args):
    pool, images = _load_pool(args.binary, _scan_opts(args))
    disp = jop.find_dispatchers(pool, img=images[0])
    t = Table(title="JOP dispatcher gadgets (self-advancing jmp/call-through-register)")
    t.add_column("address")
    t.add_column("gadget")
    t.add_column("reg")
    t.add_column("advance")
    for d in disp[: args.limit]:
        t.add_row(f"0x{d.gadget.address:x}", escape(d.gadget.text), d.reg, f"0x{d.advance:x}")
    console.print(t)
    console.print(f"[bold]{len(disp)}[/bold] dispatcher(s) found")


def cmd_onegadget(args):
    img = loader.load(args.binary)
    if img.arch not in ("x86_64", "x86"):
        console.print(f"[red]one-gadget search is scoped to x86/x86-64 (target is {img.arch})[/red]")
        sys.exit(1)
    console.print("[dim]searching for shell-string references and emulating forward "
                  "from each one -- this concretely runs the real code, so it can take "
                  "a few seconds...[/dim]")
    rep = onegadget.find_one_gadgets(img, max_insns=args.max_insns)
    t = Table(title="one-gadgets (empirically confirmed via emulation, not a curated database)")
    t.add_column("address")
    t.add_column("string")
    t.add_column("starting state that worked")
    t.add_column("instructions run")
    for c in rep.candidates:
        t.add_row(f"0x{c.address:x}", c.string.decode(), c.constraint, str(c.instructions_run))
    console.print(t)
    console.print(f"searched {rep.searched_sites} shell-string reference site(s), "
                   f"[bold]{len(rep.candidates)}[/bold] confirmed")


def cmd_libcid(args):
    offsets = {}
    for item in args.symbol:
        name, _, off = item.partition("=")
        if not off:
            console.print(f"[red]expected name=0xoffset, got {item!r}[/red]")
            sys.exit(1)
        offsets[name] = int(off, 0)
    try:
        matches = libcdb.identify(offsets)
    except ConnectionError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if not matches:
        console.print("[yellow]no matching libc build found[/yellow]")
        return
    for m in matches:
        console.print(f"[bold]{m.id}[/bold]  buildid={m.buildid}")
        console.print(f"  download: {m.download_url}")
        for k, v in sorted(m.symbols.items()):
            console.print(f"    {k} = 0x{v:x}")
    if args.download:
        if len(matches) > 1:
            console.print(f"[yellow]{len(matches)} matches -- downloading the first ({matches[0].id})[/yellow]")
        path = libcdb.download(matches[0], args.download)
        console.print(f"[green]saved to {path}[/green]")


def cmd_srop(args):
    pool, images = _load_pool(args.binary, _scan_opts(args))
    if pool.ai.arch != "x86_64":
        console.print("[red]SROP support here is scoped to Linux x86-64[/red]")
        sys.exit(1)
    args_list = [int(a, 0) for a in args.args.split(",")] if args.args else [0, 0, 0]
    while len(args_list) < 3:
        args_list.append(0)
    res = srop.build_srop_execve(pool, path_ptr=args_list[0], argv_ptr=args_list[1], envp_ptr=args_list[2])
    for l in res.solve.log:
        console.print(f"[dim]{l}[/dim]")
    if not res.ok:
        console.print(f"[red]could not build SROP chain: {res.solve.unresolved}[/red]")
        sys.exit(1)
    console.print(output.stack_layout(res.chain), markup=False)
    expect = {"rax": 59, "rdi": args_list[0], "rsi": args_list[1], "rdx": args_list[2]}
    consistent = srop.verify_srop_frame(res.chain, res.frame_offset_words, expect)
    console.print(f"\nframe self-consistency check: {'[green]OK[/green]' if consistent else '[red]FAIL[/red]'}")
    if args.verify:
        ok, result = srop.emulate_srop_chain(images[0], res.chain, expect)
        console.print(f"emulated (simulated sigreturn semantics -- see srop.py docstring): "
                       f"{'[green]OK[/green]' if ok else '[red]FAIL[/red]'}")
    if args.emit:
        _emit(res.chain, args.emit, args.out)


def _emit(chain, fmt: str, out: str | None):
    if fmt == "pwntools":
        text = output.to_pwntools(chain)
    elif fmt == "c":
        text = output.to_c_array(chain)
    elif fmt == "json":
        text = output.to_json(chain)
    elif fmt == "raw":
        data = output.to_raw(chain)
        if out:
            with open(out, "wb") as f:
                f.write(data)
            console.print(f"[green]wrote {len(data)} raw bytes to {out}[/green]")
        else:
            sys.stdout.buffer.write(data)
        return
    else:
        raise ValueError(fmt)
    if out:
        with open(out, "w") as f:
            f.write(text)
        console.print(f"[green]wrote to {out}[/green]")
    else:
        console.print(text, markup=False)


def _do_verify(images, chain, final_target, goal_regs):
    rep = verify_chain(images[0], chain, final_target=final_target, goal_regs=goal_regs)
    console.print(f"\n[bold]-- concrete verification (Unicorn) --[/bold]")
    console.print(f"reached target: {rep.reached_target}   fault: {rep.fault}   "
                   f"insns executed: {rep.instructions_executed}")
    for reg, (ok, want, got) in rep.goal_results.items():
        mark = "[green]OK[/green]" if ok else "[red]MISMATCH[/red]"
        console.print(f"  {reg}: expected 0x{want:x}, got "
                       f"{'0x%x' % got if got is not None else '?'}  {mark}")
    if rep.fault:
        console.print(f"[red]fault at 0x{rep.fault_address:x} near: {rep.last_gadget_context}[/red]")
    console.print(f"[bold]{'PASS' if rep.ok else 'FAIL'}[/bold]")


def cmd_call(args):
    pool, images = _load_pool(args.binary, _scan_opts(args))
    target = int(args.target, 0) if args.target.startswith("0x") or args.target.isdigit() else None
    if target is None:
        for img in images:
            if args.target in img.symbols:
                target = img.symbols[args.target]
                break
        if target is None:
            console.print(f"[red]symbol {args.target!r} not found[/red]")
            sys.exit(1)
    args_list = [int(a, 0) for a in args.args.split(",")] if args.args else []
    res = callchain.build_call(pool, target, args_list)
    for l in res.solve.log:
        console.print(f"[dim]{l}[/dim]")
    if not res.ok:
        console.print(f"[red]could not build call chain; unresolved: {res.solve.unresolved}[/red]")
        sys.exit(1)
    console.print(output.stack_layout(res.chain), markup=False)
    if args.emit:
        _emit(res.chain, args.emit, args.out)
    if args.verify:
        goal = {r: v for r, v in zip(pool.ai.call_arg_regs, args_list)}
        _do_verify(images, res.chain, target, goal)


def cmd_syscall(args):
    pool, images = _load_pool(args.binary, _scan_opts(args))
    args_list = [int(a, 0) for a in args.args.split(",")] if args.args else []
    res = syscallchain.build_syscall(pool, args.nr, args_list)
    for l in res.solve.log:
        console.print(f"[dim]{l}[/dim]")
    if not res.ok:
        console.print(f"[red]could not build syscall chain; unresolved: {res.solve.unresolved}[/red]")
        sys.exit(1)
    console.print(output.stack_layout(res.chain), markup=False)
    if args.emit:
        _emit(res.chain, args.emit, args.out)
    if args.verify:
        _do_verify(images, res.chain, res.gadget_addr, {})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ropnroll", description="ROP/JOP gadget finder and chain synthesizer")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--max-insns", type=int, default=6)
    common.add_argument("--no-rop", action="store_true")
    common.add_argument("--no-jop", action="store_true")
    common.add_argument("--no-sys", action="store_true")
    common.add_argument("--bad-bytes", help="hex string, e.g. 000a0d")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", parents=[common])
    s.add_argument("binary")
    s.add_argument("--regex")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--out")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("security", parents=[common])
    s.add_argument("binary")
    s.set_defaults(func=cmd_security)

    s = sub.add_parser("search", parents=[common])
    s.add_argument("binary", nargs="+")
    s.add_argument("--query", required=True, help='e.g. "rdi=rax+8", "[rbx]=rax", "rax=0"')
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("pivot", parents=[common])
    s.add_argument("binary", nargs="+")
    s.add_argument("--limit", type=int, default=30)
    s.set_defaults(func=cmd_pivot)

    s = sub.add_parser("jop", parents=[common])
    s.add_argument("binary", nargs="+")
    s.add_argument("--limit", type=int, default=30)
    s.set_defaults(func=cmd_jop)

    s = sub.add_parser("onegadget")
    s.add_argument("binary")
    s.add_argument("--max-insns", type=int, default=2000,
                    help="instruction budget per candidate site during emulation")
    s.set_defaults(func=cmd_onegadget)

    s = sub.add_parser("srop", parents=[common], help="build a sigreturn-oriented execve chain")
    s.add_argument("binary", nargs="+")
    s.add_argument("--args", default="", help="path_ptr,argv_ptr,envp_ptr (comma-separated)")
    s.add_argument("--emit", choices=["pwntools", "raw", "c", "json"])
    s.add_argument("--out")
    s.add_argument("--verify", action="store_true")
    s.set_defaults(func=cmd_srop)

    s = sub.add_parser("libcid", help="identify a libc build from leaked symbol offsets via libc.rip")
    s.add_argument("--symbol", action="append", required=True,
                    help="name=0xoffset (offset from the leaked libc's own base), repeatable")
    s.add_argument("--download", metavar="PATH", help="save the (first) matched libc here")
    s.set_defaults(func=cmd_libcid)

    s = sub.add_parser("call", parents=[common])
    s.add_argument("binary", nargs="+")
    s.add_argument("--target", required=True, help="address (0x...) or symbol name")
    s.add_argument("--args", default="", help="comma-separated integers, e.g. 0x1000,0,0")
    s.add_argument("--emit", choices=["pwntools", "raw", "c", "json"])
    s.add_argument("--out")
    s.add_argument("--verify", action="store_true")
    s.set_defaults(func=cmd_call)

    s = sub.add_parser("syscall", parents=[common])
    s.add_argument("binary", nargs="+")
    s.add_argument("--nr", type=int, required=True)
    s.add_argument("--args", default="")
    s.add_argument("--emit", choices=["pwntools", "raw", "c", "json"])
    s.add_argument("--out")
    s.add_argument("--verify", action="store_true")
    s.set_defaults(func=cmd_syscall)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
