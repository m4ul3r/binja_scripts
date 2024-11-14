from pathlib import Path

winja_path = Path.home() / "Documents" / "winja_bndbs"
winja_path.mkdir(parents=True, exist_ok=True)


def add_analysis_to_bv(bv, dll_bv, dll_name):
    # create segments
    i = 0
    for seg in dll_bv.segments:
        # map memory segment
        br = BinaryReader(dll_bv)
        br.seek(seg.start)
        bv.memory_map.add_memory_region(
            dll_name + str(i), seg.start, br.read(seg.length)
        )
        i += 1

        # create user memory segment
        flags = 0
        if seg.readable:
            flags += 4
        if seg.writable:
            flags += 2
        if seg.executable:
            flags += 1
        bv.add_user_segment(seg.start, seg.length, seg.start, seg.length, flags)

    # create sections
    for name, section in dll_bv.sections.items():
        bv.add_user_section(
            dll_name + name,
            section.start,
            section.length,
            section.semantics,
            section.type,
            section.align,
            section.entry_size,
        )

    # merge types
    for name, typ in dll_bv.types:
        bv.define_user_type(name, typ)

    # merge functions
    for func in dll_bv.functions:
        bv.add_function(func.start, func.platform)

    # merge symbols
    for name, syms in dll_bv.symbols.items():
        for sym in syms:
            bv.define_auto_symbol(sym)


print("[+] Starting Merge")

# skip binary and ntdll
for mod in dbg.modules[1:-1]:
    dll_path = Path(mod.name)
    winja_bndb = str(winja_path / dll_path.name) + ".bndb"
    # check if bndb is cache
    if Path(winja_bndb).exists():
        dll_bv = load(winja_bndb)
        print(f"[+] Loaded bndb: {winja_bndb}")
    else:
        dll_bv = load(mod.name)
        dll_bv.update_analysis_and_wait()
        dll_bv.save(winja_bndb)
        print(f"[+] Saved bndb: {winja_bndb}")

    # rebase dll
    dll_bv = dll_bv.rebase(mod.address, True)

    add_analysis_to_bv(bv, dll_bv, dll_path.name)
    print(f"[+] Added {dll_path.name} to bv")

# handle ntdll
mod = dbg.modules[-1]
dll_path = Path(Path("C:\\Windows\\System32") / mod.name)
winja_bndb = str(winja_path / dll_path.name) + ".bndb"
# check if bndb is cache
if Path(winja_bndb).exists():
    dll_bv = load(winja_bndb)
    print(f"[+] Loaded bndb: {winja_bndb}")
else:
    dll_bv = load(dll_path)
    dll_bv.update_analysis_and_wait()
    dll_bv.save(winja_bndb)
    print(f"[+] Saved bndb: {winja_bndb}")

# rebase dll
dll_bv = dll_bv.rebase(mod.address, True)

add_analysis_to_bv(bv, dll_bv, dll_path.name)
print(f"[+] Added {dll_path.name} to bv")

print("[+] Merge Finished")
