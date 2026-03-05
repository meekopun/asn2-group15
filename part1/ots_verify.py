#!/usr/bin/env python3
import sys
import hashlib


def chain_hash(data: bytes, steps: int) -> bytes:
    # apply SHA-256 <steps> times
    for _ in range(steps):
        data = hashlib.sha3_256(data).digest()
    return data


def hash_file_sha3_256(path: str) -> bytes:
    with open(path, "rb") as f:
        msg = f.read()
    return hashlib.sha3_256(msg).digest()


def digest_to_nibbles_be(digest32: bytes) -> list[int]:
    # digest32 is 32 bytes, want 64 nibbles
    d = []
    for b in digest32:
        d.append((b >> 4) & 0x0F)
        d.append(b & 0x0F)
    return d


def read_exact_blocks(path: str, nblocks: int, block_size: int) -> list[bytes] | None:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != nblocks * block_size:
        return None
    blocks = []
    for i in range(nblocks):
        start = i * block_size
        end = (i + 1) *block_size
        blocks.append(data[start:end])

    return blocks


def main():
    if len(sys.argv) != 4:
        print("INVALID")
        return

    message_file = sys.argv[1]
    public_key_file = sys.argv[2]
    signature_file = sys.argv[3]

    try:
        h = hash_file_sha3_256(message_file)
        d = digest_to_nibbles_be(h)

        pk_blocks = read_exact_blocks(public_key_file, 64, 32)
        sig_blocks = read_exact_blocks(signature_file, 64, 32)

        if pk_blocks is None or sig_blocks is None:
            print("INVALID")
            return

        for i in range(64):
            steps = 16 - d[i]       # 16 - d[i]
            computed = chain_hash(sig_blocks[i], steps)
            if computed != pk_blocks[i]:
                print("INVALID")
                return

        print("VALID")

    except Exception:
        print("INVALID")


if __name__ == "__main__":
    main()