import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


from decimal import Decimal, InvalidOperation
import re


def analyze(data):
    content = text(data)
    require(content and not content.startswith("#"), "bodyfile11_required")
    records, events, identities = [], {}, {}
    for line_no, line in enumerate(content.splitlines(), 1):
        require(line_no <= MAX_RECORDS and len(line) <= 65536, "record_limit")
        require(line and not any(ord(c) < 32 for c in line), "invalid_line")
        fields = line.split("|")
        require(len(fields) == 11, "bodyfile_field_count")
        digest, name, inode, mode, uid, gid, size, *times = fields
        require(
            digest == "0" or bool(re.fullmatch(r"[0-9A-Fa-f]{32}", digest)),
            "invalid_md5_declaration",
        )
        require(name and len(name) <= 32768, "invalid_name")
        require(
            len(inode) <= 128 and re.fullmatch(r"[0-9]+(?:-[0-9]+)*", inode),
            "invalid_inode",
        )
        require(re.fullmatch(r"[drlbcpshV?\-][rwxstST?\-]{9}", mode), "invalid_mode")
        require(
            all(re.fullmatch(r"[0-9]+", x) for x in (uid, gid, size)),
            "invalid_numeric_field",
        )
        require(all(len(x) <= 20 for x in (uid, gid, size)), "numeric_length")
        require(all(int(x) <= 2**64 - 1 for x in (uid, gid, size)), "numeric_range")
        stamps = []
        for item in times:
            require(
                len(item) <= 24 and re.fullmatch(r"-?[0-9]+(?:\.[0-9]{1,9})?", item),
                "invalid_timestamp",
            )
            try:
                stamp = Decimal(item)
            except InvalidOperation:
                raise Invalid("invalid_timestamp") from None
            require(
                Decimal("-62135596800") <= stamp <= Decimal("253402300799"),
                "timestamp_range",
            )
            stamps.append(stamp)
        ident = (name, inode)
        declaration = tuple(fields[:7])
        require(
            ident not in identities or identities[ident] == declaration,
            "conflicting_identity_declaration",
        )
        identities[ident] = declaration
        for label, stamp in zip("amcb", stamps):
            if stamp != 0:
                key = (stamp, line_no)
                events.setdefault(key, []).append(label)
        records.append(
            {
                "line": line_no,
                "name_characters": len(name),
                "declared_size": int(size),
                "nonzero_times": sum(x != 0 for x in stamps),
                "md5_declared": digest != "0",
            }
        )
    require(records, "no_records")
    timeline = [
        {"time_unix": str(stamp), "line": line, "events": "".join(labels)}
        for (stamp, line), labels in sorted(events.items())
    ]
    return {
        "records": records,
        "timeline": timeline,
        "record_count": len(records),
        "scope": "Bodyfile 11-column declarations and sorted timeline; timestamps do not prove activity or tampering.",
    }
