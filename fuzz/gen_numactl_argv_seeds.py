#!/usr/bin/env python3
"""Generate the seed corpus for fuzz_numactl_argv.

Deterministic argv vectors (NUL-separated tokens) that cover the numactl
option state machine: policy options, node/cpu strings (incl. the
netdev:/file:/ip:/block:/pci: affinity forms and relative/inverted ranges),
--show/--hardware reporting, --shm/--file setup and dump/verify paths.

Usage: gen_numactl_argv_seeds.py <output zip>
"""
import sys
import zipfile


def argv(*tokens):
    """argv("--show") -> b"--show\\x00\" ..."""
    return ("\x00".join(tokens) + "\x00").encode()


SEEDS = {
    "show": argv("--show"),
    "hardware": argv("--hardware"),
    "hardware_compress": argv("--hardware", "--cpu-compress"),
    "version": argv("--version"),
    "physcpubind_cmd": argv("-C", "0-3", "--", "/bin/true"),
    "cpunodebind_cmd": argv("-N", "0", "/bin/true"),
    "membind_cmd": argv("--membind=all", "/bin/true"),
    "interleave_all": argv("-i", "all", "/bin/true"),
    "localalloc": argv("--localalloc", "/bin/true"),
    "balancing": argv("--balancing", "/bin/true"),
    "preferred": argv("--preferred=0", "--show"),
    "preferred_many": argv("--preferred-many", "0", "/bin/true"),
    "weighted_show": argv("--weighted-interleave=0", "--show"),
    "weighted_weights": argv("-w", "0-1", "-b", "/bin/true"),
    "all_flag_first": argv("--all", "-i", "all", "/bin/true"),
    "relative_range": argv("-N", "+0", "/bin/true"),
    "inverted_range": argv("-m", "!0", "/bin/true"),
    "netdev_affinity": argv("-p", "netdev:lo", "--show"),
    "file_affinity": argv("-m", "file:/etc/hosts", "/bin/true"),
    "ip_affinity": argv("-i", "ip:127.0.0.1", "/bin/true"),
    "block_affinity": argv("-p", "block:sda", "--show"),
    "pci_affinity": argv("-m", "pci:0000:00:02.0", "/bin/true"),
    "same_keyword": argv("-i", "0", "-p", "same", "/bin/true"),
    "shm_dump": argv("--shm", "/tmp/numactl-fuzz-seg", "--length", "1M",
                     "--touch", "--dump"),
    "file_dump": argv("--file", "/tmp/numactl-fuzz-file", "--offset", "4K",
                      "--length", "8K", "--dump"),
    "shm_verify": argv("--strict", "-i", "0", "--file",
                       "/tmp/numactl-fuzz-file2", "--verify"),
    "shm_mode_id": argv("--shmmode", "0644", "--shmid", "123", "--shm",
                        "/tmp/numactl-fuzz-seg2", "--dump-shm"),
    "huge_touch": argv("--huge", "--touch", "--file", "/tmp/numactl-fuzz-huge",
                       "--length", "4M", "--dump"),
    "bigmemsize": argv("--length", "9223372036854775807G", "--file",
                       "/tmp/numactl-fuzz-big", "--dump"),
    "policy_conflict": argv("-i", "0", "-m", "0", "/bin/true"),
    "cpu_compress_only": argv("--cpu-compress"),
    "dump_no_shm": argv("--dump"),
    "shmmode_only": argv("--shmmode", "0777"),
    "two_policies_show": argv("-i", "0", "-w", "0"),
}


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    with zipfile.ZipFile(sys.argv[1], "w") as zf:
        for name, blob in SEEDS.items():
            zf.writestr(name, blob)
    print("wrote %d seeds to %s" % (len(SEEDS), sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
