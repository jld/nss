import os
import sys
import struct
import subprocess

OBJDUMP = "objdump"
OBJDUMP_DISAS = [OBJDUMP, "--prefix-addresses", "-j", ".text", "-d"]
PLT_COV_POINT = "<__sanitizer_cov@plt>\n"
INT_COV_POINT = "<__sanitizer_cov>\n"

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
                print e
                continue
    return data

def is_cov_point(line):
    return line.endswith(PLT_COV_POINT) or line.endswith(INT_COV_POINT)

def read_bin_file(path):
    proc = subprocess.Popen(OBJDUMP_DISAS + [path], stdout = subprocess.PIPE)
    try:
        sys.stderr.write("Reading coverage points from %s... " % path)
        points = set()
        last_insn_was_cov = False
        for line in proc.stdout:
            if last_insn_was_cov:
                addr = int(line.split(" ", 1)[0], 16)
                points.add(addr - 1)
            last_insn_was_cov = is_cov_point(line)
        sys.stderr.write("done.")
        return points
    except Exception:
        proc.kill()
        raise
    finally:
        sys.stderr.write("\n")
        proc.communicate()

def is_elf_file(path):
    if os.path.isfile(path):
        with open(path) as f:
            return f.read(4) == "\x7FELF"

def read_bin_tree(path):
    bins = dict()
    for (dirpath, subdirnames, filenames) in os.walk(path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if not is_elf_file(filepath):
                continue
            if filename in bins:
                # FIXME: warn or something? could be same file multiply linked
                continue
            bins[filename] = read_bin_file(filepath)
    return bins

if __name__ == '__main__':
    print read_sancov_tree(sys.argv[1])
