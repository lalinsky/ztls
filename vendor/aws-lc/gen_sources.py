#!/usr/bin/env python3
"""Generates sources.zig from AWS-LC's own CMake build.

AWS-LC's file lists live in CMake, and which files a target gets depends on
its OS and architecture. Rather than re-derive that, this configures the
upstream CMake project once per supported target (configure only, nothing is
compiled), reads compile_commands.json and writes the C files, the assembly
files and the defines for each target into sources.zig.

Usage:
    python3 gen_sources.py /path/to/aws-lc > sources.zig

Requires cmake, ninja and zig on PATH, and NASM on PATH or in $NASM. The
assembly comes from AWS-LC's pre-generated `generated-src/`, so neither Perl
nor Go is needed.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

# (zig name, zig target triple, CMake system name, CMake processor, asm dir)
TARGETS = [
    ("x86_64_linux", "x86_64-linux-gnu", "Linux", "x86_64", "linux-x86_64"),
    ("aarch64_linux", "aarch64-linux-gnu", "Linux", "aarch64", "linux-aarch64"),
    ("aarch64_macos", "aarch64-macos", "Darwin", "arm64", "ios-aarch64"),
    ("x86_64_macos", "x86_64-macos", "Darwin", "x86_64", "mac-x86_64"),
    ("aarch64_windows", "aarch64-windows-gnu", "Windows", "ARM64", "win-aarch64"),
    ("x86_64_windows", "x86_64-windows-gnu", "Windows", "AMD64", "win-x86_64"),
]

# Defines that every target gets from the build script itself, or that only
# make sense for CMake's own build.
SKIP_DEFINES = {"NDEBUG"}

# libssl files left out: the I/O libssl does by itself. ztls hands libssl
# its transport through a BIO of its own and loads certificates and keys
# itself, so nothing here is ever called.
SKIP_SSL = {
    "ssl/bio_ssl.cc",  # BIO_f_ssl, an SSL object wrapped as a BIO
    "ssl/ssl_file.cc",  # the *_file loaders, through stdio
    "ssl/ssl_decrepit.c",  # SSL_add_dir_cert_subjects_to_stack, opendir
}


def configure(src, work, name, triple, system, processor):
    def wrapper(driver):
        path = os.path.join(work, f"{driver}-{name}.sh")
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\nexec zig {driver} -target {triple} -Wno-unknown-warning-option -Wno-gcc-install-dir-libstdcxx "$@"\n')
        os.chmod(path, 0o755)
        return path

    cc = wrapper("cc")
    cxx = wrapper("c++")
    noop = os.path.join(work, "noop.sh")
    with open(noop, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(noop, 0o755)

    build = os.path.join(work, f"build-{name}")
    args = [
        "cmake", "-GNinja", "-S", src, "-B", build,
        f"-DCMAKE_SYSTEM_NAME={system}",
        f"-DCMAKE_SYSTEM_PROCESSOR={processor}",
        f"-DCMAKE_C_COMPILER={cc}",
        f"-DCMAKE_CXX_COMPILER={cxx}",
        f"-DCMAKE_ASM_COMPILER={cc}",
        f"-DCMAKE_INSTALL_NAME_TOOL={noop}",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DDISABLE_GO=ON",
        "-DDISABLE_PERL=ON",
        "-DBUILD_TESTING=OFF",
        "-DBUILD_LIBSSL=ON",
        "-DBUILD_TOOL=OFF",
        # Seeds the per-thread DRBG from the OS, rather than from CPU jitter
        # with a read of RDRAND (or RNDR) on every RAND_bytes call, which
        # is slow where RDRAND is. Jitter is only needed for FIPS.
        "-DDISABLE_CPU_JITTER_ENTROPY=ON",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]
    if system == "Darwin":
        args.append(f"-DCMAKE_OSX_ARCHITECTURES={processor}")
    if system == "Windows" and processor == "AMD64":
        # Upstream's x86_64 Windows assembly is NASM. Configuring only
        # needs a NASM to exist; the Zig build assembles with its own.
        args.append(f"-DNASM_EXECUTABLE={nasm()}")
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)
    with open(os.path.join(build, "compile_commands.json")) as f:
        return build, json.load(f)


def nasm():
    path = os.environ.get("NASM") or shutil.which("nasm")
    if not path:
        raise SystemExit("x86_64 Windows needs NASM to configure: put it on PATH or set NASM")
    return path


def relpath(path, src, build, asm_dir):
    """Maps a compiled file back to its place in the source tree."""
    path = os.path.normpath(path)
    src = os.path.normpath(src)
    build = os.path.normpath(build)
    if path.startswith(src + os.sep):
        return os.path.relpath(path, src)
    rel = os.path.relpath(path, build)
    if rel == os.path.join("crypto", "err_data.c"):
        return os.path.join("generated-src", "err_data.c")
    if rel.endswith((".S", ".asm")) and rel.startswith("crypto" + os.sep):
        # CMake copies generated-src/<platform>/crypto/ into the build tree.
        candidate = os.path.join("generated-src", asm_dir, rel)
        if os.path.exists(os.path.join(src, candidate)):
            return candidate
    raise SystemExit(f"cannot map {path} back to the source tree")


def collect(src, build, commands, asm_dir):
    c_files, ssl_files, asm_files = [], [], []
    defines = None
    for cmd in commands:
        rel = relpath(cmd["file"], src, build, asm_dir)
        if os.sep + "test" + os.sep in rel and "trampoline" in rel:
            continue  # test-only assembly
        if rel.endswith((".S", ".asm")):
            asm_files.append(rel)
        elif rel.startswith("ssl" + os.sep):
            if rel not in SKIP_SSL:
                ssl_files.append(rel)
        else:
            c_files.append(rel)
            if "BORINGSSL_IMPLEMENTATION" in cmd["command"]:
                flags = shlex.split(cmd["command"])
                d = sorted(t[2:] for t in flags if t.startswith("-D") and t[2:] not in SKIP_DEFINES)
                if defines is None:
                    defines = d
    return sorted(c_files), sorted(ssl_files), sorted(asm_files), defines


def zig_list(name, items):
    out = [f"    .{name} = &.{{"]
    out += [f'        "{i}",' for i in items]
    out.append("    },")
    return "\n".join(out)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    src = os.path.abspath(sys.argv[1])
    version = subprocess.run(
        ["git", "-C", src, "describe", "--tags", "--always"],
        capture_output=True, text=True,
    ).stdout.strip() or "unknown"

    targets = []
    with tempfile.TemporaryDirectory() as work:
        for name, triple, system, processor, asm_dir in TARGETS:
            build, commands = configure(src, work, name, triple, system, processor)
            targets.append((name, collect(src, build, commands, asm_dir)))

    # The C and C++ files are the same everywhere; only the assembly and a
    # few defines depend on the target. Checked rather than assumed, so an
    # upstream change that breaks it shows up here.
    _, (c_files, ssl_files, _, _) = targets[0]
    for name, (c, s, _, _) in targets:
        if c != c_files:
            raise SystemExit(f"{name}: C sources differ from {targets[0][0]}")
        if s != ssl_files:
            raise SystemExit(f"{name}: libssl sources differ from {targets[0][0]}")

    out = [
        "//! Generated by gen_sources.py from AWS-LC " + version + ". Do not edit.",
        "",
        "pub const Target = struct {",
        "    @\"asm\": []const []const u8,",
        "    defines: []const []const u8,",
        "};",
        "",
        "pub const c: []const []const u8 = &.{",
    ]
    out += [f'    "{f}",' for f in c_files]
    out += ["};", ""]
    out += [
        "/// libssl, all C++.",
        "pub const ssl: []const []const u8 = &.{",
    ]
    out += [f'    "{f}",' for f in ssl_files]
    out += ["};", ""]
    for name, (_, _, a, d) in targets:
        out.append(f"pub const {name}: Target = .{{")
        out.append(zig_list("@\"asm\"", a))
        out.append(zig_list("defines", d))
        out.append("};")
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
