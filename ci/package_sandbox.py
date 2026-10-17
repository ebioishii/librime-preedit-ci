"""Inspect official Weasel binaries and package only after all CI gates pass."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

INSTALLER = "weasel-0.17.4.0-installer.exe"
INSTALLER_SHA = "cf509534a8f5f8af9c98ed7cbb8f135439f145a8cbe7e50ede42bb5b5ab45c29"
PATCH_SHA = "d73347abe76dc87fef859b5a63dedeb571a796009265ddf4d4c404bb3ac888ca"
PINNED = {
    "librime": "1c23358157934bd6e6d6981f0c0164f05393b497",
    "librime/plugins/lua": "e3912a4b3ac2c202d89face3fef3d41eb1d7fcd6",
    "librime/plugins/lua/thirdparty": "115e000c878d1170337f7ca934d7a84f68986e39",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


class PE:
    # Read only PE metadata. No official installer or Weasel EXE is executed.
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        require(self.data[:2] == b"MZ", f"Not a PE file: {path}")
        pe = self.u32(0x3C)
        require(self.data[pe:pe + 4] == b"PE\0\0", f"Invalid PE: {path}")
        self.machine, count = struct.unpack_from("<HH", self.data, pe + 4)
        optional_size = self.u16(pe + 20)
        opt = pe + 24
        self.is64 = self.u16(opt) == 0x20B
        self.directories = opt + (112 if self.is64 else 96)
        section = opt + optional_size
        self.sections = [struct.unpack_from("<IIII", self.data, section + i * 40 + 8)
                         for i in range(count)]

    def u16(self, offset):
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset):
        return struct.unpack_from("<I", self.data, offset)[0]

    def offset(self, rva):
        for virtual_size, address, size, raw in self.sections:
            if address <= rva < address + max(virtual_size, size):
                return raw + rva - address
        raise RuntimeError(f"Unmapped PE RVA {rva:x} in {self.path}")

    def string(self, rva):
        start = self.offset(rva)
        return self.data[start:self.data.index(b"\0", start)].decode("ascii")

    def imports(self):
        result = {}
        for index, delayed in ((1, False), (13, True)):
            rva = self.u32(self.directories + index * 8)
            if not rva:
                continue
            cursor = self.offset(rva)
            while True:
                values = struct.unpack_from("<8I" if delayed else "<5I", self.data, cursor)
                if not any(values):
                    break
                if delayed:
                    require(values[0] & 1, "Unsupported VA-based delay imports")
                    name, thunk = values[1], values[4]
                else:
                    thunk, _, _, name, first = values
                    thunk = thunk or first
                symbols = result.setdefault(self.string(name).lower(), [])
                pointer = self.offset(thunk)
                width = 8 if self.is64 else 4
                while True:
                    value = struct.unpack_from("<Q" if self.is64 else "<I", self.data, pointer)[0]
                    if not value:
                        break
                    symbols.append("#" + str(value & 0xFFFF) if value >> (width * 8 - 1)
                                   else self.string(value + 2))
                    pointer += width
                cursor += 32 if delayed else 20
        return result

    def exports(self):
        rva = self.u32(self.directories)
        require(rva != 0, f"No exports: {self.path}")
        base, count, names, functions, name_rvas, ordinals = struct.unpack_from(
            "<6I", self.data, self.offset(rva) + 16)
        result = {"#" + str(base + i) for i in range(count)
                  if self.u32(self.offset(functions) + i * 4)}
        result.update(self.string(self.u32(self.offset(name_rvas) + i * 4))
                      for i in range(names))
        return result


def diagnose_installer():
    # Evidence only: no DLL loading, candidate selection, build, or packaging.
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    installer = root / "weasel-official" / INSTALLER
    require(sha(installer) == INSTALLER_SHA, "Official installer hash mismatch")
    require(sha(root / "librime-1.13.1-preedit-fallback.patch") == PATCH_SHA, "Patch changed")
    output = root / "installer-diagnostics"
    require(not output.exists(), "Refusing to reuse a diagnostics directory")
    output.mkdir()

    def seven_zip(arguments, log_name):
        command = ["7z", *arguments, "-sccUTF-8"]
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
        (output / log_name).write_text(result.stdout, encoding="utf-8")
        require(result.returncode == 0, f"7-Zip failed ({result.returncode}); see {log_name}")
        return result.stdout

    version = seven_zip(["i"], "7zip-version-and-formats.txt")
    listing = seven_zip(["l", "-slt", str(installer)], "installer-full-list-slt.txt")

    def related(name):
        name = name.casefold()
        return ("weaselserver" in name or "weaseldeployer" in name
                or ("rime" in name and ".dll" in name))

    archive_entries = []
    for block in re.split(r"\r?\n\s*\r?\n", listing):
        fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        if "Path" in fields and "Type" not in fields:
            archive_entries.append(fields)
    require(archive_entries, "No archive entries parsed; raw SLT listing is retained")
    by_path = {}
    for entry in archive_entries:
        by_path.setdefault(entry["Path"].replace("\\", "/").casefold(), []).append(entry)

    machines = {0x014C: "I386", 0x8664: "AMD64", 0xAA64: "ARM64",
                0xA641: "ARM64EC", 0xA64E: "ARM64X"}
    inventories = {}
    file_lists = {}
    for label, switch in (("original-y", "-y"), ("preserve-aou", "-aou")):
        directory = root / "weasel-official" / label
        require(not directory.exists(), f"Refusing to reuse extraction directory: {label}")
        directory.mkdir()
        seven_zip(["x", str(installer), f"-o{directory}", switch], f"extract-{label}.log")
        inventory = []
        file_list = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            record = {"relative_path": path.relative_to(directory).as_posix(),
                      "actual_name": path.name, "bytes": path.stat().st_size,
                      "sha256": sha(path)}
            file_list.append(dict(record))
            if not related(path.name):
                continue
            try:
                pe = PE(path)
                record.update(machine=f"0x{pe.machine:04X}",
                              machine_name=machines.get(pe.machine, "UNKNOWN"),
                              optional_header="PE32+" if pe.is64 else "PE32")
            except (RuntimeError, struct.error, ValueError, IndexError) as error:
                record["pe_error"] = str(error)
            inventory.append(record)
        inventories[label] = inventory
        file_lists[label] = file_list
        (output / f"files-{label}.json").write_text(
            json.dumps(file_list, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    original_hashes = {record["sha256"] for record in inventories["original-y"]}
    report = {
        "ci_commit": os.environ.get("GITHUB_SHA"),
        "installer_sha256": sha(installer),
        "patch_sha256": PATCH_SHA,
        "seven_zip_version": next(line.strip() for line in version.splitlines() if "7-Zip" in line),
        "archive_entry_count": len(archive_entries),
        "related_archive_entries": [entry for entry in archive_entries if related(entry["Path"])],
        "duplicate_archive_paths": {key: value for key, value in by_path.items() if len(value) > 1},
        "extracted_file_counts": {label: len(files) for label, files in file_lists.items()},
        "inventories": inventories,
        "additional_contents_preserved_by_aou": [record for record in inventories["preserve-aou"]
                                                if record["sha256"] not in original_hashes],
        "compatibility_checked": False,
        "package_created": False,
        "note": "Substring matches are inventory only; production selection logic is unchanged.",
    }
    (output / "installer-diagnosis.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("DIAGNOSTIC_REPORT " + json.dumps(report, ensure_ascii=False))


def api_probe(dll, header):
    require(ctypes.sizeof(ctypes.c_void_p) == 8, "Probe must run as x64")
    # The unchanged pinned header defines the exact API-table field order.
    source = header.read_text(encoding="utf-8")
    body = source.split("typedef struct RIME_FLAVORED(rime_api_t) {", 1)[1].split(
        "} RIME_FLAVORED(RimeApi)", 1)[0]
    fields = re.findall(r"\(\*(\w+)\)", body)
    class Api(ctypes.Structure):
        _fields_ = [("data_size", ctypes.c_int)] + [(name, ctypes.c_void_p) for name in fields]
    # Only the DLL's own directory and Windows System32 may satisfy dependencies.
    lib = ctypes.WinDLL(str(dll.resolve()), winmode=0x00000100 | 0x00000800)
    lib.rime_get_api.restype = ctypes.POINTER(Api)
    table = lib.rime_get_api().contents
    require(table.data_size == ctypes.sizeof(Api) - ctypes.sizeof(ctypes.c_int),
            f"Unexpected RimeApi size: {table.data_size}")
    reserved = {"commit_proto", "context_proto", "status_proto"}
    require(all(getattr(table, field) for field in fields if field not in reserved),
            "Null non-reserved RimeApi function pointer")
    version = ctypes.CFUNCTYPE(ctypes.c_char_p)(table.get_version)().decode("ascii")
    require(version == "1.13.1", f"Unexpected core version: {version}")
    return {"version": version, "api_data_size": table.data_size,
            "api_function_count": len(fields), "loader_search": "DLL directory + System32"}


def main():
    if sys.argv[1:] == ["--diagnose-installer"]:
        diagnose_installer()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "--probe":
        print(json.dumps(api_probe(Path(sys.argv[2]), Path(sys.argv[3]))))
        return
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    os.chdir(root)
    installer = root / "weasel-official" / INSTALLER
    require(sha(installer) == INSTALLER_SHA, "Official installer hash mismatch")
    require(sha(root / "librime-1.13.1-preedit-fallback.patch") == PATCH_SHA, "Patch changed")
    for directory, expected in PINNED.items():
        require(git(root / directory, "rev-parse", "HEAD") == expected, f"Wrong revision: {directory}")
    tests = {}
    for group, expected in (("preedit", 4), ("lua", 2), ("core", 87)):
        report = ET.parse(root / f"windows-{group}-results.xml").getroot()
        cases = list(report.iter("testcase"))
        ran = [c for c in cases if c.get("status") == "run"]
        require(len(ran) == expected and not list(report.iter("failure"))
                and not list(report.iter("error")) and not list(report.iter("skipped")),
                f"Test gate failed: {group}")
        tests[group] = {"passed": len(ran), "failed": 0, "not_run": len(cases) - len(ran)}

    extracted = root / "weasel-official" / "extracted"
    official = {}
    for name in ("WeaselServer.exe", "WeaselDeployer.exe"):
        matches = [p for p in extracted.rglob(name) if PE(p).machine == 0x8664]
        require(len(matches) == 1, f"Expected one official x64 {name}, found {matches}")
        official[name] = matches[0]
    original = official["WeaselServer.exe"].parent / "rime.dll"
    require(PE(original).machine == 0x8664, "Official core is not x64")
    candidate = root / "librime" / "dist" / "lib" / "rime.dll"
    require(PE(candidate).machine == 0x8664, "Patched core is not x64")
    exported = PE(candidate).exports()
    imports = {}
    for name, executable in official.items():
        required = PE(executable).imports().get("rime.dll")
        require(required and not (set(required) - exported), f"Unsatisfied Rime imports in {name}: {required}")
        imports[name] = {"machine": "AMD64", "sha256": sha(executable), "rime_imports": required}

    # Staging is never uploaded if any later check fails.
    stage = root / "sandbox-staging"
    require(not stage.exists(), "Refusing to reuse an existing staging directory")
    runtime = stage / "patched-x64"
    runtime.mkdir(parents=True)
    shutil.copy2(candidate, runtime / "rime.dll")
    dependencies = {}
    pending = [runtime / "rime.dll"]
    while pending:
        binary = pending.pop()
        for name in PE(binary).imports():
            if name in dependencies:
                continue
            require(not re.match(r"(?:vcruntime|msvcp|concrt)\d", name),
                    f"Unexpected VC runtime dependency requiring separate redistribution: {name}")
            if name.startswith(("api-ms-win-", "ext-ms-win-")) or (Path(os.environ["SystemRoot"]) / "System32" / name).is_file():
                dependencies[name] = "Windows system component; not redistributed"
                continue
            candidates = [root / "librime" / d / name for d in ("dist/lib", "build/bin", "bin", "lib")]
            available = [p for p in candidates if p.is_file()]
            require(available, f"Missing runtime dependency: {name}")
            require(len({sha(p) for p in available}) == 1, f"Conflicting runtime dependency: {name}")
            require(PE(available[0]).machine == 0x8664, f"Non-x64 dependency: {name}")
            target = runtime / name
            shutil.copy2(available[0], target)
            dependencies[name] = "bundled in patched-x64"
            pending.append(target)

    header = root / "librime/src/rime_api.h"
    def probe(dll):
        # Separate processes prevent same-name original/patched DLL interference.
        return json.loads(subprocess.check_output(
            [sys.executable, str(Path(__file__).resolve()), "--probe", str(dll), str(header)], text=True))
    original_probe = probe(original)
    patched_probe = probe(runtime / "rime.dll")
    require(original_probe == patched_probe, "Original/patched API probe differs")

    notices = stage / "licenses"
    sources = {"librime": root / "librime", "librime-lua": root / "librime/plugins/lua",
               "Lua-5.4.7": root / "librime/plugins/lua/thirdparty"}
    submodules = git(root / "librime", "submodule", "status", "--recursive")
    for line in submodules.splitlines():
        path = line.split()[1]
        sources[path.replace("/", "_")] = root / "librime" / path
    for label, directory in sources.items():
        for relative in git(directory, "ls-files").splitlines():
            path = directory / relative
            if path.is_file() and re.match(r"(?:LICENSE|COPYING|COPYRIGHT|NOTICE)(?:[._-]|$)", path.name, re.I):
                target = notices / label / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
    boost_notice = root / "librime/deps/boost-1.84.0/LICENSE_1_0.txt"
    require(boost_notice.is_file(), "Missing Boost license")
    shutil.copy2(boost_notice, notices / "Boost-LICENSE_1_0.txt")
    shutil.copy2(root / "librime/plugins/lua/thirdparty/lua5.4/lua.h", notices / "Lua-5.4.7-license-in-lua.h")
    (stage / "official").mkdir()
    shutil.copy2(installer, stage / "official" / INSTALLER)
    shutil.copy2(root / "ci/Sandbox-steps.txt", stage / "Sandbox-steps.txt")
    (stage / "Sandbox.wsb").write_text(
        '<Configuration>\n  <Networking>Disable</Networking>\n'
        '  <ClipboardRedirection>Disable</ClipboardRedirection>\n'
        '  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n'
        '  <MappedFolders><MappedFolder>\n'
        '    <HostFolder>C:\\REPLACE_WITH_TEST_PACKAGE_FOLDER</HostFolder>\n'
        '    <SandboxFolder>C:\\SandboxInput</SandboxFolder>\n'
        '    <ReadOnly>true</ReadOnly>\n'
        '  </MappedFolder></MappedFolders>\n</Configuration>\n', encoding="utf-8")
    run_url = f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    manifest = {"ci_commit": os.environ["GITHUB_SHA"], "ci_run": run_url, "architecture": "x64",
                "source_commits": PINNED, "patch_sha256": PATCH_SHA,
                "lua_version": "5.4.7", "boost_version": "1.84.0", "configuration": "MSVC Release",
                "weasel_version": "0.17.4", "weasel_source_commit": "9cc96e20dc71b80876b12f689bb5863c76c2a7ed",
                "compiler": subprocess.run(["cl"], capture_output=True, text=True, errors="replace").stderr.splitlines(),
                "cmake": subprocess.check_output(["cmake", "--version"], text=True).splitlines()[0],
                "ninja": subprocess.check_output(["ninja", "--version"], text=True).strip(),
                "dependency_commits": submodules.splitlines(),
                "official_installer_url": "https://github.com/rime/weasel/releases/download/0.17.4/" + INSTALLER,
                "official_installer_sha256": INSTALLER_SHA, "official_original_rime_sha256": sha(original),
                "weasel_import_checks": imports, "official_core_probe": original_probe,
                "patched_core_probe": patched_probe, "runtime_dependencies": dependencies, "tests": tests,
                "limits": ["Official installer and Weasel executables were not executed.",
                           "No Weasel UI/TSF or Sandbox acceptance has been performed.",
                           "No private configuration, dictionary or Onion Lua is included.",
                           "OpenCC/schema data are supplied by the unmodified official installer."]}
    (stage / "versions-and-checks.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    files = [p for p in sorted(stage.rglob("*")) if p.is_file()]
    inventory = [{"path": p.relative_to(stage).as_posix(), "bytes": p.stat().st_size, "sha256": sha(p)} for p in files]
    (stage / "file-list.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (stage / "SHA256SUMS.txt").write_text("".join(
        f"{sha(p)}  {p.relative_to(stage).as_posix()}\n" for p in sorted(stage.rglob("*")) if p.is_file()), encoding="utf-8")
    output = root / "sandbox-output"
    output.mkdir()
    archive = output / "weasel-0.17.4-preedit-x64-sandbox.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(stage).as_posix())
    with zipfile.ZipFile(archive) as z:
        require(z.testzip() is None, "ZIP integrity test failed")
    (output / (archive.name + ".sha256")).write_text(f"{sha(archive)}  {archive.name}\n", encoding="ascii")
    for name in ("versions-and-checks.json", "file-list.json", "SHA256SUMS.txt", "Sandbox-steps.txt"):
        shutil.copy2(stage / name, output / name)
    print(json.dumps(manifest, ensure_ascii=False))
    print("PACKAGE_SHA256 " + sha(archive))
    print("PATCHED_RIME_SHA256 " + sha(runtime / "rime.dll"))
    print("PACKAGE_FILES " + json.dumps(inventory, ensure_ascii=False))


if __name__ == "__main__":
    main()
