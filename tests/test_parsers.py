from __future__ import annotations

from serverscope.collector.linux import parsers

DF_OUTPUT = """Filesystem     Type 1024-blocks     Used Available Capacity Mounted on
/dev/sda1      ext4    51474912 20589964  28248568      43% /
/dev/sdb1      xfs    103081248 92773123  10308125      91% /data
"""

FREE_OUTPUT = """              total        used        free      shared  buff/cache   available
Mem:    16777216000  8388608000  4194304000   100000000  4194304000  7500000000
Swap:    2147483648   214748364  1932735284
"""


def test_split_sections() -> None:
    out = "junk\n===a===\nhello\nworld\n===b===\n42"
    sections = parsers.split_sections(out)
    assert sections["a"] == "hello\nworld"
    assert sections["b"] == "42"


def test_parse_os_release() -> None:
    name, version = parsers.parse_os_release('NAME="Ubuntu"\nVERSION_ID="22.04"\n')
    assert name == "Ubuntu"
    assert version == "22.04"


def test_parse_df() -> None:
    filesystems = parsers.parse_df(DF_OUTPUT)
    assert len(filesystems) == 2
    root = filesystems[0]
    assert root.mount == "/"
    assert root.fstype == "ext4"
    assert 39 < root.used_pct < 41
    assert filesystems[1].used_pct > 89


def test_parse_free() -> None:
    mem = parsers.parse_free(FREE_OUTPUT)
    assert mem["total"] == 16777216000
    assert mem["swap_total"] == 2147483648


def test_cpu_pct_from_stat_pair() -> None:
    s1 = "cpu  100 0 100 800 0 0 0 0 0 0"
    s2 = "cpu  200 0 200 1500 50 0 0 50 0 0"
    pct = parsers.cpu_pct_from_stat_pair(s1, s2)
    total = 100 + 100 + 700 + 50 + 50
    assert abs(pct["usage_pct"] - 100 * 250 / total) < 0.01
    assert pct["steal_pct"] > 0


def test_parse_loadavg() -> None:
    assert parsers.parse_loadavg("0.52 0.58 0.59 1/467 12345") == (0.52, 0.58, 0.59)


def test_parse_ss_summary() -> None:
    assert parsers.parse_ss_summary("TCP:   85 (estab 12, closed 60)") == 12


def test_parse_ps() -> None:
    output = (
        "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        "root 1234 55.0 2.1 1000 2000 ? S 10:00 1:00 /usr/bin/stress --cpu 4\n"
    )
    procs = parsers.parse_ps(output)
    assert procs[0].pid == 1234
    assert procs[0].cpu_pct == 55.0


def test_disk_rates_from_pair() -> None:
    d1 = "   8  0 sda 100 0 2048 0 200 0 4096 0 0 0 0\n"
    d2 = "   8  0 sda 200 0 4096 0 300 0 8192 0 0 0 0\n"
    rates = parsers.disk_rates_from_pair(d1, d2, interval=2.0)
    assert rates["iops_read"] == 50.0
    assert rates["iops_write"] == 50.0


def test_net_rates_from_pair() -> None:
    d1 = "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n    lo: 999999 0 0 0 0 0 0 0 999999 0 0 0 0 0 0 0\n"
    d2 = "  eth0: 3000 30 0 0 0 0 0 0 6000 60 0 0 0 0 0 0\n    lo: 999999 0 0 0 0 0 0 0 999999 0 0 0 0 0 0 0\n"
    rates = parsers.net_rates_from_pair(d1, d2, interval=2.0)
    assert rates["rx_bytes_per_sec"] == 1000.0
    assert rates["tx_bytes_per_sec"] == 2000.0
