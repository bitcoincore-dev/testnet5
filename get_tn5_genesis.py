import hashlib
import socket
import struct
import time

HOST = "tn5.21m.dev"
PORT = 18353
MAGIC = bytes.fromhex("46495645")  # Testnet 5 magic bytes ("FIVE")
MSG_BLOCK = 2


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def make_msg(command, payload=b""):
    cmd = command.encode("ascii").ljust(12, b"\x00")
    checksum = sha256d(payload)[:4]
    return MAGIC + cmd + struct.pack("<I", len(payload)) + checksum + payload


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed by peer")
        buf += chunk
    return buf


def read_msg(sock):
    header = recv_exact(sock, 24)
    magic, cmd, length, checksum = struct.unpack("<4s12sI4s", header)
    if magic != MAGIC:
        raise ValueError(f"Unexpected network magic: {magic.hex()}")
    payload = recv_exact(sock, length)
    return cmd.rstrip(b"\x00").decode("ascii"), payload


def read_varint(buf, offset):
    first = buf[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        return struct.unpack("<H", buf[offset + 1 : offset + 3])[0], offset + 3
    elif first == 0xfe:
        return struct.unpack("<I", buf[offset + 1 : offset + 5])[0], offset + 5
    else:
        return struct.unpack("<Q", buf[offset + 1 : offset + 9])[0], offset + 9


def build_version_payload():
    version = 70016
    services = 0
    timestamp = int(time.time())
    addr_recv = struct.pack("<Q16sH", 0, b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1"), PORT)
    addr_from = struct.pack("<Q16sH", 0, b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1"), 0)
    nonce = 123456789
    user_agent = b"/tn5-fetcher:0.2/"
    start_height = 0
    relay = 0
    return (
        struct.pack("<iQQ", version, services, timestamp)
        + addr_recv
        + addr_from
        + struct.pack("<Q", nonce)
        + bytes([len(user_agent)])
        + user_agent
        + struct.pack("<i?", start_height, relay)
    )


def parse_genesis_block(block_bytes):
    # 80-byte block header
    header = block_bytes[:80]
    version, prev_block, merkle_root, ntime, nbits, nnonce = struct.unpack("<i32s32sIII", header)
    genesis_hash = sha256d(header)[::-1].hex()

    # Transaction count and coinbase tx parsing
    tx_count, offset = read_varint(block_bytes, 80)
    tx_version = struct.unpack("<i", block_bytes[offset : offset + 4])[0]
    offset += 4

    # Check for SegWit marker/flag (0x00, 0x01)
    has_witness = False
    if block_bytes[offset] == 0x00 and block_bytes[offset + 1] == 0x01:
        has_witness = True
        offset += 2

    # Inputs (1 coinbase input)
    vin_count, offset = read_varint(block_bytes, offset)
    offset += 36  # 32-byte null prevout + 4-byte vout index (0xffffffff)
    scriptsig_len, offset = read_varint(block_bytes, offset)
    scriptsig = block_bytes[offset : offset + scriptsig_len]
    offset += scriptsig_len + 4  # scriptSig + 4-byte sequence

    # Outputs (coinbase output containing commitment Pubkey)
    vout_count, offset = read_varint(block_bytes, offset)
    value = struct.unpack("<Q", block_bytes[offset : offset + 8])[0]
    offset += 8
    pk_len, offset = read_varint(block_bytes, offset)
    script_pubkey = block_bytes[offset : offset + pk_len]

    print("=== Live Testnet 5 Genesis Block Parameters ===")
    print(f"Genesis Hash:    {genesis_hash}")
    print(f"Merkle Root:     {merkle_root[::-1].hex()}")
    print(f"nVersion:        {version}")
    print(f"nTime:           {ntime}")
    print(f"nBits:           0x{nbits:08x}")
    print(f"nNonce:          {nnonce}")
    print(f"Coinbase Value:  {value} satoshis")
    print(f"ScriptSig (hex): {scriptsig.hex()}")
    print(f"ScriptPubKey:    {script_pubkey.hex()}")


def main():
    genesis_hash_le = None

    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(make_msg("version", build_version_payload()))

        while True:
            cmd, payload = read_msg(s)
            if cmd == "version":
                s.sendall(make_msg("verack"))
            elif cmd == "verack":
                gh_payload = struct.pack("<IB", 70016, 1) + (b"\x00" * 32) + (b"\x00" * 32)
                s.sendall(make_msg("getheaders", gh_payload))
            elif cmd == "headers":
                count, offset = read_varint(payload, 0)
                if count == 0:
                    raise RuntimeError("Peer returned 0 headers.")
                block1_header = payload[offset : offset + 80]
                _, prev_block, _, _, _, _ = struct.unpack("<i32s32sIII", block1_header)
                genesis_hash_le = prev_block

                # Request the full genesis block via getdata
                gd_payload = struct.pack("<BI", 1, MSG_BLOCK) + genesis_hash_le
                s.sendall(make_msg("getdata", gd_payload))
            elif cmd == "block":
                parse_genesis_block(payload)
                break


if __name__ == "__main__":
    main()
