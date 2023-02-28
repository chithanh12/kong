#!/usr/bin/env python3

import os
import re
import sys
import glob
import atexit
import difflib
import inspect
import argparse
import datetime
import tempfile
from pathlib import Path

import lief
from elftools.elf.elffile import ELFFile
from globmatch import glob_match
from inspect import getframeinfo

import config


class ExplainOpts():
    # General
    owners = True
    mode = True
    size = False
    # ELF
    merge_rpaths_runpaths = False
    imported_symbols = False
    exported_symbols = False
    version_requirement = True

    @classmethod
    def from_args(this, args):
        this.owners = args.owners
        this.mode = args.mode
        this.size = args.size
        this.merge_rpaths_runpaths = args.merge_rpaths_runpaths
        this.imported_symbols = args.imported_symbols
        this.exported_symbols = args.exported_symbols
        this.version_requirement = args.version_requirement

        return this


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--path", "-p", help="Path to the directory to compare", required=True)
    parser.add_argument(
        "--output", "-o", help="Path to output manifest, use - to write to stdout", default="-")
    parser.add_argument(
        "--file_list", "-f", help="Path to the files list to explain for manifest; " + \
                                    "each line in the file should be a glob pattern of full path")
    parser.add_argument(
        "--owners", help="Export and compare owner and group", action="store_true")
    parser.add_argument(
        "--mode", help="Export and compare mode", action="store_true")
    parser.add_argument(
        "--size", help="Export and compare size", action="store_true")
    parser.add_argument("--merge_rpaths_runpaths",
                        help="Treate RPATH and RUNPATH as same", action="store_true")
    parser.add_argument(
        "--imported_symbols", help="Export and compare imported symbols", action="store_true")
    parser.add_argument(
        "--exported_symbols", help="Export and compare exported symbols", action="store_true")
    parser.add_argument("--version_requirement",
                        help="Export and compare exported symbols (default to True)",
                        action="store_true", default=True)

    return parser.parse_args()


def read_glob(path):
    if not path:
        return ["**"]

    with open(path, "r") as f:
        return f.read().splitlines()


def gather_files(path):
    ext = os.path.splitext(path)[1]
    if ext in (".deb", ".rpm") or path.endswith(".apk.tar.gz"):
        t = tempfile.TemporaryDirectory()
        atexit.register(t.cleanup)

        if ext == ".deb":
            code = os.system(
                "ar p %s data.tar.gz | tar -C %s -xz" % (path, t.name))
        elif ext == ".rpm":
            # GNU cpio and rpm2cpio is needed
            code = os.system(
                "rpm2cpio %s | cpio --no-preserve-owner --no-absolute-filenames -idm -D %s" % (path, t.name))
        elif ext == ".gz":
            code = os.system("tar -C %s -xf %s" % (t.name, path))

        if code != 0:
            raise Exception("Failed to extract %s" % path)

        return t.name
    elif not Path(path).is_dir():
        raise Exception("Don't know how to process \"%s\"" % path)

    return path


class FileInfo():
    def __init__(self, path, relpath):
        self.path = path
        self.relpath = relpath
        self.mode = os.stat(path).st_mode
        self.uid = os.stat(path).st_uid
        self.gid = os.stat(path).st_gid
        self.size = os.stat(path).st_size

        if Path(path).is_symlink():
            self.link = os.readlink(path)
        elif Path(path).is_dir():
            self.directory = True

    def explain(self, opts):
        lines = [("Path", self.relpath)]
        if hasattr(self, "link"):
            lines.append(("Link", self.link))
            lines.append(("Type", "link"))
        elif hasattr(self, "directory"):
            lines.append(("Type", "directory"))

        if opts.owners:
            lines.append(("Uid,Gid",  "%s, %s" % (self.uid, self.gid)))
        if opts.mode:
            lines.append(("Mode", oct(self.mode)))
        if opts.size:
            lines.append(("Size", self.size))

        return lines


class ElfFileInfo(FileInfo):
    def __init__(self, path, relpath):
        super().__init__(path, relpath)

        self.needed = []
        self.rpath = None
        self.runpath = None
        self.get_exported_symbols = None
        self.get_imported_symbols = None
        self.version_requirement = []

        binary = lief.parse(path)
        if not binary:  # not an ELF file, malformed, etc
            return

        for d in binary.dynamic_entries:
            if d.tag == lief.ELF.DYNAMIC_TAGS.NEEDED:
                self.needed.append(d.name)
            elif d.tag == lief.ELF.DYNAMIC_TAGS.RPATH:
                self.rpath = d.name
            elif d.tag == lief.ELF.DYNAMIC_TAGS.RUNPATH:
                self.runpath = d.name

        # create closures and lazily evaluated
        self.get_exported_symbols = lambda: sorted(
            [d.name for d in binary.exported_symbols])
        self.get_imported_symbols = lambda: sorted(
            [d.name for d in binary.imported_symbols])

        for f in binary.symbols_version_requirement:
            self.version_requirement.append("%s (%s)" % (
                f.name, ", ".join(sorted([a.name for a in f.get_auxiliary_symbols()]))))
        self.version_requirement = sorted(self.version_requirement)

    def explain(self, opts):
        pline = super().explain(opts)

        lines = []

        if self.needed:
            lines.append(("Needed", self.needed))
        if self.rpath:
            lines.append(("Rpath", self.rpath))
        if self.runpath:
            lines.append(("Runpath", self.runpath))
        if opts.exported_symbols and self.get_exported_symbols:
            lines.append(("Exported", self.get_exported_symbols()))
        if opts.imported_symbols and self.get_imported_symbols:
            lines.append(("Imported", self.get_imported_symbols()))
        if opts.version_requirement and self.version_requirement:
            lines.append(("Version Requirement", self.version_requirement))

        return pline + lines


class NginxInfo(ElfFileInfo):
    def __init__(self, path, relpath):
        super().__init__(path, relpath)

        self.nginx_modules = []
        self.nginx_compiled_openssl = None

        binary = lief.parse(path)

        for s in binary.strings:
            if re.match("\s*--prefix=/", s):
                for m in re.findall("add(?:-dynamic)?-module=(.*?) ", s):
                    if m.startswith("../"):  # skip bundled modules
                        continue
                    pdir = os.path.basename(os.path.dirname(m))
                    mname = os.path.basename(m)
                    if pdir in ("external", "distribution"):
                        self.nginx_modules.append(mname)
                    else:
                        self.nginx_modules.append(os.path.join(pdir, mname))
                self.nginx_modules = sorted(self.nginx_modules)
            elif m := re.match("^built with (.+) \(running with", s):
                self.nginx_compiled_openssl = m.group(1).strip()

        # Fetch DWARF infos
        with open(path, "rb") as f:
            elffile = ELFFile(f)
            self.has_dwarf_info = elffile.has_dwarf_info()
            self.has_ngx_http_request_t_DW = False
            dwarf_info = elffile.get_dwarf_info()
            for cu in dwarf_info.iter_CUs():
                dies = [die for die in cu.iter_DIEs()]
                # Too many DIEs in the binary, we just check those in `ngx_http_request`
                if "ngx_http_request" in dies[0].attributes['DW_AT_name'].value.decode('utf-8'):
                    for die in dies:
                        value = die.attributes.get('DW_AT_name') and die.attributes.get('DW_AT_name').value.decode('utf-8')
                        if value and value == "ngx_http_request_t":
                            self.has_ngx_http_request_t_DW = True

    def explain(self, opts):
        pline = super().explain(opts)

        lines = []
        lines.append(("Nginx Modules", self.nginx_modules))
        lines.append(("Nginx OpenSSL", self.nginx_compiled_openssl))
        lines.append(("Nginx DWARF", self.has_dwarf_info))
        lines.append(("Nginx DWARF - ngx_http_request_t related DWARF DIEs", self.has_ngx_http_request_t_DW))

        return pline + lines


def walk_files(path, globs):
    results = []
    for file in sorted(glob.glob("**", root_dir=path, recursive=True)):
        if not glob_match(file, globs):
            continue

        full_path = os.path.join(path, file)

        if not file.startswith("/") and not file.startswith("./"):
            file = '/' + file  # prettifier

        if os.path.basename(file) == "nginx":
            f = NginxInfo(full_path, file)
        elif os.path.splitext(file)[1] == ".so" or os.path.basename(os.path.dirname(file)) in ("bin", "lib", "lib64", "sbin"):
            p = Path(full_path)
            if p.is_symlink():
                continue
            f = ElfFileInfo(full_path, file)
        else:
            f = FileInfo(full_path, file)

        config.transform(f)
        results.append(f)

    return results


def write_manifest(title, results, opts: ExplainOpts, output):
    if output == "-":
        f = sys.stdout
    else:
        f = open(output, "w")

    print("# Manifest for %s\n\n" % title)

    for result in results:
        entries = result.explain(opts)
        ident = 2
        first = True
        for k, v in entries:
            if isinstance(v, list):
                v = ("\n" + " " * ident + "- ").join([""] + v)
            else:
                v = " %s" % v
            if first:
                f.write("-" + (" " * (ident-1)))
                first = False
            else:
                f.write(" " * ident)
            f.write("%-10s:%s\n" % (k, v))
        f.write("\n")

    f.flush()

    if f != sys.stdout:
        f.close()

def write_color(color):
    term_colors = {
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "magenta": 35,
        "cyan": 36,
        "white": 37,
    }
    def decorator(fn):
        def wrapper(self, *args):
            if color not in term_colors:
                raise ValueError("unknown color %s" % color)
            sys.stdout.write('\033[%dm' % term_colors[color])
            r = fn(self, *args)
            sys.stdout.write('\033[0m')
            return r
        return wrapper
    return decorator


class ExpectChain():
    def __init__(self, infos):
        self._infos = infos
        self._all_failures = []
        self._reset()
        atexit.register(self._print_all_fails)

    def _reset(self):
        self._logical_reverse = False
        self._files = []
        self._msg = ""
        self._title_shown = False
        self._checks_count = 0

    def _ctx_info(self):
        f = inspect.currentframe().f_back.f_back.f_back.f_back
        fn_rel = os.path.relpath(getframeinfo(f).filename, os.getcwd())

        return "%s:%d" % (fn_rel, f.f_lineno)
    
    def _log(self, *args):
        sys.stdout.write(" %s " % datetime.datetime.now().strftime('%b %d %X'))
        print(*args)
    
    @write_color("white")
    def _print_title(self):
        if self._title_shown:
            return
        self._log("[TEST] running %s: %s" % (self._ctx_info(), self._msg))
        self._title_shown = True

    @write_color("red")
    def _print_fail(self, msg):
        self._log("[FAIL] %s" % msg)
        self._all_failures.append("%s: %s" % (self._ctx_info(), msg))

    @write_color("green")
    def _print_ok(self):
        self._log("[OK  ] %d check(s) passed for %d file(s)" % (self._checks_count, len(self._files)))
    
    @write_color("red")
    def _print_all_fails(self):
        if self._all_failures:
            print("\nFollowing failure(s) occured:\n" + "\n".join(self._all_failures))
            os._exit(1)

    def _compare(self, attr, fn):
        self._checks_count += 1
        for f in self._files:
            if not hasattr(f, attr):
                continue # accept missing attribute for now
            v = getattr(f, attr)
            (ok, err_template) = fn(v)
            if not ok:
                self._print_fail("file %s <%s>: %s" % (f.relpath, attr, err_template.format(v)))
                return False
        return True

    def _equal(self, attr, expect):
        return self._compare(attr, lambda a: (a == expect, "{} doesn't equal to %s" % expect))

    def _match(self, attr, expect):
        return self._compare(attr, lambda a: (re.match(expect, a), "{} doesn't match %s" % expect))

    def _contain(self, attr, expect):
        def fn(a):
            if isinstance(a, list):
                ok = expect in a
                if not ok:
                    closed = difflib.get_close_matches(expect, a, 1)
                    if len(a) == 0:
                        msg = "%s is empty" % attr
                    elif len(closed) > 0:
                        msg = "did you mean '%s'?" % closed[0]
                    else:
                        msg = "%s is not found in the list" % expect
                    return ok, msg
            else:
                return False, "%s is not a list" % attr
            return True, None
        return self._compare(attr, fn)

    def _contain_match(self, attr, expect):
        def fn(a):
            if isinstance(a, list):
                for e in a:
                    if re.match(expect, e):
                        return True, None
            else:
                return False, "%s is not a list" % attr
        return self._compare(attr, fn)
    
    # following are public methods (test functions)

    def expect(self, path_glob, msg):
        self._reset()
        self._msg = msg

        for f in self._infos:
            if glob_match(f.relpath, [path_glob]):
                self._files.append(f)
        return self

    def do_not(self):
        self._logical_reverse = True
        return self
    
    def __getattr__(self, name):
        self._print_title()

        m = re.findall(r"([a-z]+)(_equal|_match|_contain|_contain_match)", name)
        if not m:
            self._print_fail("unknown test function \"%s\"" % name)
            return lambda *x: self

        attr, op = m[0]
        for f in self._files:
            if not hasattr(f, attr):
                self._print_fail("\"%s\" expect \"%s\" attribute to be present, but it's not for %s" % (name, attr, f.path))
                return lambda *x: self

        def cls(expect):
            result = getattr(self, op)(attr, expect)
            if result != self._logical_reverse:
                self._print_ok()
            return self

        return cls


if __name__ == "__main__":
    args = parse_args()

    globs = read_glob(args.file_list)

    directory = gather_files(args.path)

    infos = walk_files(directory, globs)

    if Path(args.path).is_file():
        title = "contents in archive %s" % args.path
    else:
        title = "contents in directory %s" % args.path

    # write_manifest(title, infos, ExplainOpts.from_args(args), args.output)

    E = ExpectChain(infos)
    E.expect("**/nginx", "nginx rpath should contain kong lib") \
        .rpath_equal("b")
    E.expect("**/nginx", "") \
        .rpath_equal("/usr/local/openresty/luajit/lib:/usr/local/kong/lib")
