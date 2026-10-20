"""Independent tree oracle using Python's trusted hashlib SHA-256."""
import hashlib
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def reference(data, block_size):
    level = [
        hashlib.sha256(data[i:i + block_size]).digest()
        for i in range(0, len(data), block_size)
    ]
    while len(level) > 1:
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def run(*args):
    return subprocess.run(
        [str(executable), *map(str, args)], capture_output=True, text=True
    )


def check(data, leaves, block_size, path):
    path.write_bytes(data)
    result = run(leaves, block_size, path)
    assert result.returncode == 0, result.stderr
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert fields["root"] == reference(data, block_size), (leaves, block_size)
    assert int(fields["nodes"]) == 2 * leaves - 1


executable = Path(sys.argv[1]).resolve()
rng = random.Random(5206)
cases = 0
with tempfile.TemporaryDirectory(prefix="merkle-tests-") as directory:
    path = Path(directory) / "input.bin"
    for leaves in (1, 2, 4, 16, 1024):
        for block_size in (1, 32, 55, 56, 63, 64, 65, 119, 120, 128, 256, 4096):
            data = bytes(rng.getrandbits(8) for _ in range(leaves * block_size))
            check(data, leaves, block_size, path)
            cases += 1
    for data in (b"abcd", b"abce", b"bacd", b"aaaa", b"\0" * 4):
        check(data, 4, 1, path)
        cases += 1

    # Independently reproduce the CLI's synthetic input generator.
    state = 1
    data = bytearray()
    for _ in range(8 * 32):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        data.append(state & 0xff)
    synthetic = run(8, 32)
    assert synthetic.returncode == 0, synthetic.stderr
    assert f"root={reference(data, 32)}" in synthetic.stdout

    for args in ((), ("-1", "32"), ("3", "32"), ("0", "32"), ("1", "0"),
                 ("1x", "32"), ("1", "32", path, "extra"),
                 ("18446744073709551616", "1"), ("1", "32", path / "missing")):
        assert run(*args).returncode != 0, args
    for data in (b"", b"abc", b"abcde"):
        path.write_bytes(data)
        assert run(4, 1, path).returncode != 0

print(f"Python hashlib cross-check passed: {cases} trees, synthetic input, CLI errors.")
