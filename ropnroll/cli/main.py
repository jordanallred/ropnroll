from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..core import badchars, loader, output, pattern, scanner, security
from ..semantics import query as querymod
from ..solve import callchain, jop, pivot
from ..solve.pool import GadgetPool
from ..verify.emulate import verify_chain

console = Console()
err_console = Console(stderr=True)


def _parse_base_overrides(values: list[str] | None) -> dict[str, int]:
    """`--base path=0xaddr` (repeatable) -> {path: addr}."""
    overrides: dict[str, int] = {}
    for item in values or []:
        path, _, addr = item.partition("=")
        if not addr:
            raise ValueError(f"expected path=0xaddress, got {item!r}")
        overrides[path] = int(addr, 0)
    return overrides


def _load_pool(
    paths: list[str],
    scan_opts: scanner.ScanOptions,
    use_cache: bool = True,
    base: list[str] | None = None,
    bad_chars: str | None = None,
) -> tuple[GadgetPool, list]:
    try:
        pool = GadgetPool(
            use_cache=use_cache, bad_chars=badchars.parse_bad_chars(bad_chars)
        )
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    images = []
    try:
        overrides = _parse_base_overrides(base)
        for p in paths:
            img = loader.load(p)
            if p in overrides:
                img = img.rebase(overrides[p])
            gs = scanner.scan_image(img, scan_opts, use_cache=use_cache)
            pool.add(img, gs)
            images.append(img)
    except (ValueError, FileNotFoundError, OSError) as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    return pool, images


def _scan_opts(args) -> scanner.ScanOptions:
    bad = bytes.fromhex(args.bad_bytes) if getattr(args, "bad_bytes", None) else b""
    return scanner.ScanOptions(
        max_insns=args.max_insns,
        rop=not args.no_rop,
        jop=not args.no_jop,
        sys=not args.no_sys,
        bad_bytes=bad,
        jobs=getattr(args, "jobs", None),
    )


def _addr_str(addr: int, pool: GadgetPool) -> str:
    width = pool.ai.reg_width * 2 if pool.ai else 16
    return f"0x{addr:0{width}x}"


def _clobbers_str(eff, sp_reg: str = "") -> str:
    if not eff.ok:
        return "unknown (fault)"
    regs = sorted(r for r in eff.clobbers() if r != sp_reg)
    parts = [",".join(regs)] if regs else []
    if eff.mem_writes:
        parts.append(
            f"+{len(eff.mem_writes)} mem write"
            + ("s" if len(eff.mem_writes) != 1 else "")
        )
    return " ".join(parts) if parts else "none"


def _sp_str(eff) -> str:
    if not eff.ok or eff.sp_delta is None:
        return "?"
    sign = "+" if eff.sp_delta >= 0 else "-"
    return f"{sign}0x{abs(eff.sp_delta):x}"


def _sort_gadgets(gadgets: list, by: str) -> list:
    if by == "address":
        return sorted(gadgets, key=lambda g: g.address)
    return sorted(gadgets, key=lambda g: (g.n_insns, g.address))


def _sort_note(by: str) -> str:
    return (
        "by address"
        if by == "address"
        else "best-first (fewest instructions, then address)"
    )


def _quality_style(eff, sp_reg: str = "") -> str:
    """How usable a gadget looks at a glance: red for a faulting/unknown
    effect, yellow when even the stack delta couldn't be pinned down, green
    for a clean gadget (nothing clobbered but sp, no memory writes), dim for
    one that clobbers enough to need care, and default otherwise."""
    if not eff.ok:
        return "red"
    if eff.sp_delta is None:
        return "yellow"
    regs = [r for r in eff.clobbers() if r != sp_reg]
    if not regs and not eff.mem_writes:
        return "bold green"
    if len(regs) <= 2 and not eff.mem_writes:
        return ""
    return "dim"


def _gadget_line(
    addr: str, text: str, n_insns: int, eff, sp_reg: str, text_width: int = 42
) -> str:
    line = (
        f"{addr}  {escape(text.ljust(text_width))}  "
        f"instrs={n_insns:<2} clobbers={_clobbers_str(eff, sp_reg):<18} sp={_sp_str(eff)}"
    )
    style = _quality_style(eff, sp_reg)
    return f"[{style}]{line}[/{style}]" if style else line


def cmd_scan(args):
    with console.status("[dim]scanning...[/dim]"):
        pool, images = _load_pool(
            [args.binary],
            _scan_opts(args),
            use_cache=not args.no_cache,
            base=args.base,
            bad_chars=args.bad_chars,
        )
    gadgets = pool.all()
    if args.regex:
        import re

        rx = re.compile(args.regex)
        gadgets = [g for g in gadgets if rx.search(g.text)]
    gadgets = _sort_gadgets(gadgets, args.sort)
    sp_reg = pool.ai.sp_reg if pool.ai else ""

    if args.out:
        with console.status("[dim]analyzing effects...[/dim]"):
            with open(args.out, "w") as f:
                for g in gadgets:
                    eff = pool.effect_of(g)
                    f.write(
                        f"{_addr_str(g.address, pool)} : {g.text:<42} "
                        f"instrs={g.n_insns} clobbers={_clobbers_str(eff, sp_reg)} sp={_sp_str(eff)}\n"
                    )
        console.print(
            f"[green]wrote {len(gadgets)} gadgets to {args.out}[/green], sorted {_sort_note(args.sort)}"
        )
        return

    shown = gadgets[: args.limit]
    header = f"gadgets: {args.binary}" + (
        f" matching /{args.regex}/" if args.regex else ""
    )
    console.print(f"[bold]{header}[/bold]")
    for g in shown:
        eff = pool.effect_of(g)
        console.print(
            _gadget_line(_addr_str(g.address, pool), g.text, g.n_insns, eff, sp_reg)
        )
    console.print(
        f"[bold]{len(gadgets)}[/bold] gadgets total, sorted {_sort_note(args.sort)}"
        + (f" -- showing top {args.limit}" if len(gadgets) > args.limit else "")
    )


def cmd_security(args):
    try:
        img = loader.load(args.binary)
        overrides = _parse_base_overrides(args.base)
        if args.binary in overrides:
            img = img.rebase(overrides[args.binary])
    except (ValueError, FileNotFoundError, OSError) as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    opts = _scan_opts(args)
    with console.status("[dim]scanning...[/dim]"):
        gs = scanner.scan_image(img, opts, use_cache=not args.no_cache)
    report = security.build_report(img, gs)
    t = Table(title=f"security report: {args.binary}")
    t.add_column("property")
    t.add_column("value")
    for k, v, style in report.lines:
        t.add_row(k, f"[{style}]{escape(v)}[/{style}]" if style else escape(v))
    console.print(t)


def cmd_search(args):
    with console.status("[dim]scanning and analyzing gadgets...[/dim]"):
        pool, images = _load_pool(
            args.binary,
            _scan_opts(args),
            use_cache=not args.no_cache,
            base=args.base,
            bad_chars=args.bad_chars,
        )
        try:
            results = querymod.search(pool, args.query, limit=args.limit)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
    if not results:
        console.print("[yellow]no gadgets matched[/yellow]")
        return
    sp_reg = pool.ai.sp_reg if pool.ai else ""
    console.print(f"[bold]gadgets matching {args.query!r}[/bold]")
    for g, eff, field in results:
        console.print(
            _gadget_line(_addr_str(g.address, pool), g.text, g.n_insns, eff, sp_reg)
        )
    console.print(
        f"[bold]{len(results)}[/bold] match(es), best-first (fewest instructions, then address)"
    )


def cmd_pivot(args):
    with console.status("[dim]scanning and analyzing gadgets...[/dim]"):
        pool, images = _load_pool(
            args.binary,
            _scan_opts(args),
            use_cache=not args.no_cache,
            base=args.base,
            bad_chars=args.bad_chars,
        )
        pivots = pivot.find_pivots(pool)
    t = Table(title="stack pivots (best-first)")
    t.add_column("address")
    t.add_column("gadget")
    t.add_column("instrs", justify="right")
    t.add_column("kind")
    for p in pivots[: args.limit]:
        t.add_row(
            _addr_str(p.gadget.address, pool),
            escape(p.gadget.text),
            str(p.gadget.n_insns),
            p.kind,
        )
    console.print(t)
    console.print(
        f"[bold]{len(pivots)}[/bold] pivot(s) found"
        + (f" -- showing top {args.limit}" if len(pivots) > args.limit else "")
    )


def cmd_jop(args):
    with console.status("[dim]scanning and analyzing gadgets...[/dim]"):
        pool, images = _load_pool(
            args.binary,
            _scan_opts(args),
            use_cache=not args.no_cache,
            base=args.base,
            bad_chars=args.bad_chars,
        )
        disp = jop.find_dispatchers(pool, img=images[0])
    t = Table(
        title="JOP dispatcher gadgets (self-advancing jmp/call-through-register, best-first)"
    )
    t.add_column("address")
    t.add_column("gadget")
    t.add_column("instrs", justify="right")
    t.add_column("reg")
    t.add_column("advance")
    for d in disp[: args.limit]:
        t.add_row(
            _addr_str(d.gadget.address, pool),
            escape(d.gadget.text),
            str(d.gadget.n_insns),
            d.reg,
            f"0x{d.advance:x}",
        )
    console.print(t)
    console.print(
        f"[bold]{len(disp)}[/bold] dispatcher(s) found"
        + (f" -- showing top {args.limit}" if len(disp) > args.limit else "")
    )


def _note_unresolved(chain):
    unresolved = output.unresolved_modules(chain)
    if unresolved:
        mods = ", ".join(Path(m).name for m in unresolved)
        console.print(
            f"[yellow]chain has symbolic addresses for: {mods} (base not known yet -- "
            f"pass --base <module>=0xADDR once you have a leak, or use "
            f"--emit pwntools/json for a template that resolves them at exploit time)[/yellow]"
        )


def _note_chain_warnings(chain, bad_chars: frozenset[int]):
    for w in chain.warnings:
        console.print(f"[yellow]warning: {w}[/yellow]")
    for w in badchars.chain_bad_char_warnings(chain, bad_chars):
        console.print(f"[yellow]warning: {w}[/yellow]")


def _emit(chain, fmt: str, out: str | None):
    try:
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
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if out:
        with open(out, "w") as f:
            f.write(text)
        console.print(f"[green]wrote to {out}[/green]")
    else:
        console.print(text, markup=False)


def _do_verify(images, chain, final_target, goal_regs):
    rep = verify_chain(images, chain, final_target=final_target, goal_regs=goal_regs)
    console.print("\n[bold]-- concrete verification (Unicorn) --[/bold]")
    console.print(
        f"reached target: {rep.reached_target}   fault: {rep.fault}   "
        f"instructions executed: {rep.instructions_executed}"
    )
    for reg, (ok, want, got) in rep.goal_results.items():
        mark = "[green]OK[/green]" if ok else "[red]MISMATCH[/red]"
        console.print(
            f"  {reg}: expected 0x{want:x}, got "
            f"{'0x%x' % got if got is not None else '?'}  {mark}"
        )
    if rep.fault:
        console.print(
            f"[red]fault at 0x{rep.fault_address:x} near: {rep.last_gadget_context}[/red]"
        )
    console.print(f"[bold]{'PASS' if rep.ok else 'FAIL'}[/bold]")


def cmd_call(args):
    with console.status("[dim]scanning, analyzing, and solving...[/dim]"):
        pool, images = _load_pool(
            args.binary,
            _scan_opts(args),
            use_cache=not args.no_cache,
            base=args.base,
            bad_chars=args.bad_chars,
        )
        target = (
            int(args.target, 0)
            if args.target.startswith("0x") or args.target.isdigit()
            else None
        )
        target_module = None
        if target is None:
            for img in images:
                if args.target in img.symbols:
                    target = img.symbols[args.target]
                    target_module = img.path
                    break
            if target is None:
                console.print(f"[red]symbol {args.target!r} not found[/red]")
                sys.exit(1)
        args_list = [int(a, 0) for a in args.args.split(",")] if args.args else []
        res = callchain.build_call(
            pool,
            target,
            args_list,
            bytes_before_chain=args.bytes_before_chain,
            target_module=target_module,
            img=images[0] if images else None,
        )
    for l in res.solve.log:
        console.print(f"[dim]{l}[/dim]")
    if not res.ok:
        console.print(
            f"[red]could not build call chain; unresolved: {res.solve.unresolved}[/red]"
        )
        sys.exit(1)
    console.print(output.stack_layout(res.chain), markup=False)
    _note_unresolved(res.chain)
    _note_chain_warnings(res.chain, pool.bad_chars)
    if args.emit:
        _emit(res.chain, args.emit, args.out)
    if args.verify:
        goal = {r: v for r, v in zip(callchain.arg_regs(pool.ai, pool.os), args_list)}
        _do_verify(images, res.chain, target, goal)


def cmd_pattern_create(args):
    data = pattern.create(args.length)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        console.print(
            f"[green]wrote {len(data)}-byte cyclic pattern to {args.out}[/green]"
        )
    else:
        sys.stdout.buffer.write(data)
    if args.length > pattern.PERIOD:
        err_console.print(
            f"[yellow]length {args.length} exceeds the pattern's {pattern.PERIOD}-byte "
            f"period -- it repeats past 0x{pattern.PERIOD:x}, so an offset found beyond "
            f"that point is ambiguous[/yellow]"
        )


def cmd_pattern_offset(args):
    try:
        off = pattern.offset(args.value, width=args.width, literal=args.text)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if off is None:
        console.print(
            f"[red]{args.value!r} not found in the first "
            f"0x{pattern.PERIOD:x} bytes of the pattern[/red]"
        )
        sys.exit(1)
    console.print(f"offset: [bold]{off}[/bold] (0x{off:x})")


class _Fmt(argparse.RawDescriptionHelpFormatter):
    def _format_action(self, action):
        parts = super()._format_action(action)
        if action.nargs == argparse.PARSER:
            # Drop the subparsers action's own placeholder line (its metavar,
            # e.g. "command"), keeping only the indented per-subcommand lines.
            parts = "\n".join(parts.split("\n")[1:])
        return parts


def _sub(sub, name, *, help, description=None, epilog=None, parents=()):
    return sub.add_parser(
        name,
        help=help,
        description=description or help,
        epilog=epilog,
        parents=list(parents),
        formatter_class=_Fmt,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ropnroll",
        description="ROP/JOP gadget finder and chain synthesizer.",
        epilog="Run 'ropnroll <command> --help' for that command's options and examples.",
        formatter_class=_Fmt,
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--max-insns",
        type=int,
        default=6,
        metavar="N",
        help="maximum instructions per gadget (default: 6)",
    )
    common.add_argument(
        "--no-rop", action="store_true", help="disable ROP (return-terminated) gadgets"
    )
    common.add_argument(
        "--no-jop",
        action="store_true",
        help="disable JOP (register/indirect-jump-terminated) gadgets",
    )
    common.add_argument(
        "--no-sys", action="store_true", help="disable syscall-terminated gadgets"
    )
    common.add_argument(
        "--bad-bytes",
        metavar="HEX",
        help="byte values a gadget's own instruction encoding may not contain, "
        "as hex, e.g. 000a0d (narrow scanner-level filter; for the addresses "
        "and values written into a payload, use --bad-chars instead)",
    )
    common.add_argument(
        "--bad-chars",
        metavar="HEX",
        help="byte values that must not appear in any gadget address, call "
        "target, or literal argument used in a chain -- the exploit-dev "
        "'bad char' filter (mona's --badchar), for a payload delivered "
        "through something like strcpy that mishandles them, e.g. 000a0d",
    )
    common.add_argument(
        "--no-cache",
        action="store_true",
        help="disable the persistent on-disk gadget-scan and semantic-effect caches",
    )
    common.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=None,
        metavar="N",
        help="parallel worker processes for scanning (default: auto-detect)",
    )
    common.add_argument(
        "--base",
        action="append",
        metavar="PATH=0xADDR",
        help="override a binary's load base, e.g. a leaked ASLR base "
        "for a Windows DLL (repeatable)",
    )

    sub = p.add_subparsers(
        dest="cmd", required=True, metavar="command", title="commands"
    )

    s = _sub(
        sub,
        "security",
        parents=[common],
        help="report a binary's exploit mitigations (NX, ASLR, canary, CFG, CET, SafeSEH, ...)",
        epilog="example:\n  ropnroll security ./target",
    )
    s.add_argument("binary", help="path to the binary to inspect")
    s.set_defaults(func=cmd_security)

    s = _sub(
        sub,
        "scan",
        parents=[common],
        help="list gadgets, optionally filtered by an instruction regex",
        description="List gadgets, optionally filtered by an instruction regex.\n"
        "x86 has no instruction alignment, so a regex like 'pop rdi' will\n"
        "usually match several overlapping entry points into the same tail\n"
        "bytes -- e.g. 'add rsp, 0x20 ; pop rdi ; ret' alongside a plain\n"
        "'pop rdi ; ret' a few bytes later. That's expected, not a bug: by\n"
        "default results are ranked best-first (fewest instructions, so the\n"
        "cleanest match sorts to the top) and each row shows what else the\n"
        "gadget clobbers and its net stack-pointer change, so you can tell\n"
        "at a glance which of several matches is safe to use.",
        epilog="examples:\n"
        "  ropnroll scan ./target --limit 20\n"
        "  ropnroll scan ./target --regex 'pop rdi' --out gadgets.txt",
    )
    s.add_argument("binary", help="path to the binary to scan")
    s.add_argument(
        "--regex",
        metavar="PATTERN",
        help="only show gadgets whose disassembly matches this regex",
    )
    s.add_argument(
        "--sort",
        choices=["quality", "address"],
        default="quality",
        help="'quality' ranks fewest-instructions-first, a decent proxy for the "
        "cleanest/least-clobbering gadget; 'address' is plain memory order "
        "(default: quality)",
    )
    s.add_argument(
        "--limit",
        type=int,
        default=50,
        metavar="N",
        help="max gadgets to print (default: 50)",
    )
    s.add_argument(
        "--out",
        metavar="PATH",
        help="write every matching gadget to this file instead "
        "of printing (ignores --limit)",
    )
    s.set_defaults(func=cmd_scan)

    s = _sub(
        sub,
        "search",
        parents=[common],
        help="search gadgets by their measured effect on registers or memory",
        epilog="example:\n  ropnroll search ./target --query 'rdi=rax+8'",
    )
    s.add_argument("binary", nargs="+", help="binaries to pool gadgets from")
    s.add_argument(
        "--query",
        required=True,
        metavar="EXPR",
        help='effect to match, e.g. "rdi=rax+8", "[rbx]=rax", "rax=0"',
    )
    s.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="max matches to print (default: 20)",
    )
    s.set_defaults(func=cmd_search)

    s = _sub(
        sub,
        "pivot",
        parents=[common],
        help="find stack-pivot gadgets",
        epilog="example:\n  ropnroll pivot ./target",
    )
    s.add_argument("binary", nargs="+", help="binaries to pool gadgets from")
    s.add_argument(
        "--limit",
        type=int,
        default=30,
        metavar="N",
        help="max pivots to print (default: 30)",
    )
    s.set_defaults(func=cmd_pivot)

    s = _sub(
        sub,
        "jop",
        parents=[common],
        help="find JOP dispatcher gadgets",
        description="Find JOP dispatcher gadgets: self-advancing jmp/call-through-\n"
        "register sequences used to chain JOP gadgets without a return\n"
        "address.",
        epilog="example:\n  ropnroll jop ./target",
    )
    s.add_argument("binary", nargs="+", help="binaries to pool gadgets from")
    s.add_argument(
        "--limit",
        type=int,
        default=30,
        metavar="N",
        help="max dispatchers to print (default: 30)",
    )
    s.set_defaults(func=cmd_jop)

    s = _sub(
        sub,
        "call",
        parents=[common],
        help="build a chain that calls a function by symbol or address",
        epilog="example:\n"
        "  ropnroll call ./target --target exit --args 0 --verify "
        "--emit json --out chain.json",
    )
    s.add_argument(
        "binary",
        nargs="+",
        help="binaries to pool gadgets from; the target symbol is "
        "resolved against these binaries' exports",
    )
    s.add_argument(
        "--target",
        required=True,
        metavar="ADDR|SYMBOL",
        help="address (0x...) or symbol name to call",
    )
    s.add_argument(
        "--args",
        default="",
        metavar="N,N,...",
        help="comma-separated integer arguments, e.g. 0x1000,0,0",
    )
    s.add_argument(
        "--bytes-before-chain",
        type=int,
        default=None,
        metavar="N",
        help="bytes of payload preceding this chain in the final buffer -- "
        "if given, inserts an x86-64 call-alignment correction pad when "
        "needed; omitting it warns instead of correcting",
    )
    s.add_argument(
        "--emit",
        choices=["pwntools", "raw", "c", "json"],
        help="export the chain in this format",
    )
    s.add_argument(
        "--out", metavar="PATH", help="write the emitted chain here instead of stdout"
    )
    s.add_argument(
        "--verify",
        action="store_true",
        help="concretely verify the chain with Unicorn emulation",
    )
    s.set_defaults(func=cmd_call)

    s = _sub(
        sub,
        "pattern",
        help="generate a cyclic pattern, or look up a crash offset within one",
        description="Cyclic-pattern crash-offset triage (Metasploit's pattern_create/\n"
        "pattern_offset, mona's !mona pc/po) -- no binary needed. Send\n"
        "'create's output as your crash input, then feed whatever value a\n"
        "debugger shows in the clobbered register to 'offset' to get back\n"
        "exactly how many bytes precede the data you control.",
        epilog="examples:\n"
        "  ropnroll pattern create 200 --out pattern.bin\n"
        "  ropnroll pattern offset 0x6a413169",
    )
    pattern_sub = s.add_subparsers(
        dest="pattern_cmd", required=True, metavar="subcommand"
    )

    ps = _sub(pattern_sub, "create", help="print a cyclic pattern of the given length")
    ps.add_argument("length", type=int, help="length in bytes")
    ps.add_argument(
        "--out", metavar="PATH", help="write to this file instead of stdout"
    )
    ps.set_defaults(func=cmd_pattern_create)

    ps = _sub(
        pattern_sub,
        "offset",
        help="find the byte offset of a captured value within the pattern",
    )
    ps.add_argument(
        "value",
        help="hex value as read from a clobbered register (e.g. 0x6a413169); "
        "pass --text to look up a literal pattern substring instead",
    )
    ps.add_argument(
        "--text",
        action="store_true",
        help="treat 'value' as a literal pattern substring instead of a hex value",
    )
    ps.add_argument(
        "--width",
        type=int,
        choices=[4, 8],
        default=None,
        help="value width in bytes (default: inferred from hex-digit count)",
    )
    ps.set_defaults(func=cmd_pattern_offset)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
