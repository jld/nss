import os
import re
import sys
import struct
import subprocess
import threading

try:
    from concurrent.futures import ThreadPoolExecutor
except ImportError:
    class ThreadPoolExecutor:
        def __init__(self, max_workers = None):
            pass
        def submit(self, fn, *args, **kwargs):
            fn(*args, **kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

try:
    from os import cpu_count
except ImportError:
    def cpu_count():
        return None

OBJDUMP = "objdump"
OBJDUMP_DISAS = [OBJDUMP, "--prefix-addresses", "-j", ".text", "-d"]
PLT_COV_POINT = b"<__sanitizer_cov@plt>\n"
INT_COV_POINT = b"<__sanitizer_cov>\n"

ADDR2LINE = "addr2line"
ADDR2LINE_FLAGS = "-ia"
DISCRIM_RE = re.compile("^(.*) \(discriminator (\d+)\)$")

def read_sancov_data(blob, into = None, blame = None):
    # TODO: 0xC0BF_FFFF_FFFF_FF{32,64} new-format magic.
    nbyte = len(blob)
    if (nbyte % 4) != 0:
        # FIXME: exception types
        raise Exception("length %d not divisible by 4" % l)
    offsets = into if into is not None else set()
    offsets.update(struct.unpack("=%dL" % (nbyte / 4), blob))
    return offsets

def read_sancov_tree(path, into = None):
    data = into if into is not None else dict()
    for (dirpath, dirnames, filenames) in os.walk(path):
        for filename in filenames:
            if not filename.endswith(".sancov"):
                continue
            libname = filename.rsplit(".", 2)[0]
            if libname not in data:
                data[libname] = set()
            try:
                with open(os.path.join(dirpath, filename)) as f:
                    read_sancov_data(f.read(), into = data[libname], blame = f)
            except Exception as e:
                print(e)
                continue
    return data

def is_cov_point(line):
    return line.endswith(PLT_COV_POINT) or line.endswith(INT_COV_POINT)

def cov_points(path):
    proc = subprocess.Popen(OBJDUMP_DISAS + [path], stdout = subprocess.PIPE)
    last_insn_was_cov = False
    for line in proc.stdout:
        if last_insn_was_cov:
            addr = int(line.split(b" ", 1)[0], 16)
            yield addr - 1
        last_insn_was_cov = is_cov_point(line)
    proc.wait()

def is_elf_file(path):
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return f.read(4) == b"\x7FELF"

def read_bin_tree(rootpath):
    realpath = realpath_cache()
    bins = dict()
    def do_the_thing(filename, filepath):
        sys.stderr.write("Processing: %s\n" % filepath)
        info = dict()
        gen = addr2line(filepath, cov_points(filepath))
        for (addr, srcpath, lineno, disc) in gen:
            srcpath = realpath(srcpath)
            record = (srcpath, lineno, disc)
            if addr in info:
                info[addr].append(record)
            else:
                info[addr] = [record]        
        bins[filename] = info
        sys.stderr.write("Done: %s\n" % filepath)
    with ThreadPoolExecutor(cpu_count() or 1) as e:
        for (dirpath, subdirnames, filenames) in os.walk(rootpath):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if not is_elf_file(filepath):
                    continue
                if filename in bins:
                    # FIXME: warn or something?
                    # could be same file multiply linked
                    continue
                e.submit(do_the_thing, filename, filepath)
    return bins

def addr2line(path, addr_iter):
    def write_addrs(outfd):
        for addr in addr_iter:
            outfd.write(("0x%x\n" % addr).encode())
            outfd.flush()
        outfd.close()

    proc = subprocess.Popen([ADDR2LINE, ADDR2LINE_FLAGS, "-e", path],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE)
    stdin_thread = threading.Thread(target = write_addrs,
                                    args = (proc.stdin,))
    stdin_thread.start()

    addr = None
    for outline in proc.stdout:
        outline = outline.rstrip()
        if outline.startswith(b"0x") and b":" not in outline:
            addr = int(outline, 16)
            continue
        assert addr is not None
       
        if outline.endswith(b")"):
            (outline, disc) = outline[:-1].rsplit(b" (discriminator", 1)
            disc = int(disc)
        else:
            disc = 0

        (path, lineno) = outline.rsplit(b":", 1)
        if lineno == b"?":
            lineno = b"0"
        lineno = int(lineno)
        yield (addr, path, lineno, disc)
    stdin_thread.join()
    proc.wait()

def realpath_cache():
    cache = {}
    def realpath(path):
        real = cache.get(path, None)
        if not real:
            real = os.path.realpath(path)
            cache[path] = real
        return real
    return realpath
