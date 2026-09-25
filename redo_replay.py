#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
redo_replay.py — redo 日志回放与校验工具（纯标准库，单文件）

日志格式
--------
内容行（每行一条记录）:
    <事务号> <序号> <操作> <键> [值]
    操作:
        SET <键> <值>     值允许包含空格（第 5 列起整体作为值）
        DEL <键>          删除键
        COMMIT - -        提交标记；只有提交后，该事务的操作才会被应用
注释行: 以 # 开头，忽略。
校验行（必须是日志尾部唯一的 ## 行）:
    ## CHECKSUM sha256 <内容行数N> <h1> <h2> ... <hN>
    采用逐行哈希链: h_0 = ""，h_i = sha256(h_{i-1} + "\\n" + 第 i 行原始文本) 的前 16 位。
    校验时逐行比对，第一个不一致的 i 即“从第 i 行开始不对”，
    同时也能发现日志被截断或尾部被追加。

用法
----
    python3 redo_replay.py 日志文件            校验并回放，输出重建配置与报告
    python3 redo_replay.py --strict 日志文件   校验失败即中止，不回放
    python3 redo_replay.py --sample [--gap] [--corrupt]
        生成样例日志到 stdout：--gap 含序号跳跃与未提交事务，--corrupt 篡改内容
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass, field

HASH_LEN = 16  # 链式哈希截断长度（十六进制字符数）
CHECKSUM_PREFIX = "## CHECKSUM"


def chain_hash(prev: str, raw_line: str) -> str:
    """哈希链: h_i = sha256(h_{i-1} + '\\n' + 第 i 行原始文本) 的前 HASH_LEN 位。"""
    data = (prev + "\n" + raw_line).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:HASH_LEN]


# ---------------------------------------------------------------- 数据结构

@dataclass
class Record:
    line_no: int          # 文件行号（1 起）
    idx: int              # 内容行序号（1 起，不含注释/空行/校验行）
    txn: str
    seq: int
    op: str
    key: str
    value: "str | None"


@dataclass
class ParsedLog:
    records: list = field(default_factory=list)          # list[Record]
    content_lines: list = field(default_factory=list)    # list[(line_no, raw)]
    parse_errors: list = field(default_factory=list)     # list[(line_no, msg)]
    checksum_ok: "bool | None" = None   # None 表示校验行缺失
    first_bad_idx: "int | None" = None  # 第一个不一致的内容行序号（1 起）
    checksum_msg: str = ""


# ---------------------------------------------------------------- 解析与校验

def parse_log(text: str) -> ParsedLog:
    log = ParsedLog()
    trailer = None
    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(CHECKSUM_PREFIX):
            if trailer is not None:
                log.parse_errors.append((line_no, "出现第二条约定的校验行，忽略"))
                continue
            trailer = (line_no, stripped)
            continue
        if stripped.startswith("#"):
            continue
        log.content_lines.append((line_no, raw))
        rec = _parse_record(raw, line_no, len(log.content_lines), log.parse_errors)
        if rec is not None:
            log.records.append(rec)
    _verify_checksum(log, trailer)
    return log


def _parse_record(raw, line_no, idx, errors):
    parts = raw.split(None, 4)
    if len(parts) < 3:
        errors.append((line_no, "字段不足，至少需要 事务号 序号 操作"))
        return None
    txn, seq_s, op = parts[0], parts[1], parts[2].upper()
    try:
        seq = int(seq_s)
    except ValueError:
        errors.append((line_no, f"序号 {seq_s!r} 不是整数"))
        return None
    if op == "SET":
        if len(parts) < 5:
            errors.append((line_no, "SET 缺少 键 或 值"))
            return None
        return Record(line_no, idx, txn, seq, op, parts[3], parts[4])
    if op == "DEL":
        if len(parts) < 4:
            errors.append((line_no, "DEL 缺少 键"))
            return None
        return Record(line_no, idx, txn, seq, op, parts[3], None)
    if op == "COMMIT":
        return Record(line_no, idx, txn, seq, op, "-", None)
    errors.append((line_no, f"未知操作 {parts[2]!r}（支持 SET/DEL/COMMIT）"))
    return None


def _verify_checksum(log: ParsedLog, trailer) -> None:
    if trailer is None:
        log.checksum_ok = None
        log.checksum_msg = "日志尾部缺少校验行，内容完整性无法确认"
        return
    line_no, text = trailer
    parts = text.split()
    if len(parts) < 4 or parts[1] != "CHECKSUM" or parts[2] != "sha256":
        log.checksum_ok = False
        log.checksum_msg = f"第 {line_no} 行校验行格式非法: {text!r}"
        return
    try:
        declared = int(parts[3])
    except ValueError:
        log.checksum_ok = False
        log.checksum_msg = f"第 {line_no} 行校验行中的行数非法: {parts[3]!r}"
        return
    hashes = parts[4:]
    actual = len(log.content_lines)
    if declared != actual or len(hashes) != declared:
        log.checksum_ok = False
        log.first_bad_idx = min(declared, actual) + 1
        log.checksum_msg = (
            f"校验行声明 {declared} 行/{len(hashes)} 个哈希，实际 {actual} 行："
            f"日志可能被截断或尾部被追加，从内容第 {log.first_bad_idx} 行起不可信"
        )
        return
    prev = ""
    for i, (ln, raw) in enumerate(log.content_lines):
        prev = chain_hash(prev, raw)
        if prev != hashes[i]:
            log.checksum_ok = False
            log.first_bad_idx = i + 1
            log.checksum_msg = (
                f"校验和不匹配：从内容第 {i + 1} 行（文件第 {ln} 行）开始不一致，"
                f"该行及其之后的内容均不可信"
            )
            return
    log.checksum_ok = True
    log.checksum_msg = f"校验通过（{actual} 行内容，哈希链一致）"


# ---------------------------------------------------------------- 回放

class Replayer:
    """回放策略：只有带 COMMIT 标记的事务才会应用其操作（见报告说明）。"""

    def __init__(self):
        self.state = {}        # 重建后的配置
        self.pending = {}      # txn -> [(op, key, value)] 未提交的缓冲操作
        self.next_seq = {}     # txn -> 期望的下一个序号
        self.committed = []    # 已提交事务（按提交顺序）
        self.gaps = []         # (line_no, txn, expected, actual)
        self.warnings = []     # (line_no, msg)

    def apply(self, rec: Record) -> None:
        expected = self.next_seq.get(rec.txn, 1)
        if rec.seq != expected:
            self.gaps.append((rec.line_no, rec.txn, expected, rec.seq))
        self.next_seq[rec.txn] = rec.seq + 1  # 以实际序号重新对齐，继续回放

        if rec.op == "SET":
            self.pending.setdefault(rec.txn, []).append(("SET", rec.key, rec.value))
        elif rec.op == "DEL":
            self.pending.setdefault(rec.txn, []).append(("DEL", rec.key, None))
        elif rec.op == "COMMIT":
            ops = self.pending.pop(rec.txn, [])
            for op, key, value in ops:
                if op == "SET":
                    self.state[key] = value
                elif key in self.state:
                    del self.state[key]
                else:
                    self.warnings.append((rec.line_no, f"DEL 不存在的键 {key!r}，忽略"))
            self.committed.append(rec.txn)

    @property
    def aborted(self):
        return {t: ops for t, ops in self.pending.items() if ops}


# ---------------------------------------------------------------- 样例日志

def build_sample(with_gap: bool, corrupt: bool) -> str:
    rows = [
        ("T1", 1, "SET", "db.host", "127.0.0.1"),
        ("T1", 2, "SET", "db.port", "5432"),
        ("T1", 3, "COMMIT", "-", "-"),
        ("T2", 1, "SET", "cache.enabled", "true"),
        ("T2", 2, "SET", "cache.ttl", "300"),
        ("T3", 1, "SET", "feature.beta", "on"),   # T3 没有 COMMIT：演示未提交丢弃
        ("T2", 3, "DEL", "cache.ttl", None),
        ("T2", 4, "COMMIT", "-", "-"),
    ]
    if with_gap:
        rows += [
            ("T4", 1, "SET", "demo.a", "1"),
            ("T4", 3, "SET", "demo.b", "2"),      # 序号 1 后直接 3：演示跳跃报告
            ("T4", 4, "COMMIT", "-", "-"),
        ]
    lines = []
    for txn, seq, op, key, value in rows:
        if op == "SET":
            lines.append(f"{txn} {seq} SET {key} {value}")
        elif op == "DEL":
            lines.append(f"{txn} {seq} DEL {key}")
        else:
            lines.append(f"{txn} {seq} COMMIT - -")
    hashes, prev = [], ""
    for raw in lines:
        prev = chain_hash(prev, raw)
        hashes.append(prev)
    if corrupt:  # 篡改内容但不更新校验和，演示错误定位
        lines[1] = lines[1].replace("5432", "9999")
    lines.append(f"{CHECKSUM_PREFIX} sha256 {len(hashes)} {' '.join(hashes)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 报告输出

def print_report(log: ParsedLog, rep: Replayer) -> None:
    print("========== 校验和检查 ==========")
    mark = {True: "[OK] ", False: "[FAIL] ", None: "[WARN] "}[log.checksum_ok]
    print(mark + log.checksum_msg)

    print("\n========== 回放报告 ==========")
    txns = {r.txn for r in log.records}
    print(f"内容行 {len(log.content_lines)} 条，涉及事务 {len(txns)} 个")
    print(f"已提交事务（已应用）: {', '.join(rep.committed) if rep.committed else '无'}")
    if rep.aborted:
        for txn, ops in rep.aborted.items():
            print(f"未提交事务 {txn}: {len(ops)} 条操作已丢弃（缺 COMMIT 标记，不应用）")
    else:
        print("未提交事务: 无")
    if log.parse_errors:
        print("解析错误:")
        for line_no, msg in log.parse_errors:
            print(f"  第 {line_no} 行: {msg}")
    if rep.gaps:
        print("序号跳跃:")
        for line_no, txn, exp, act in rep.gaps:
            print(f"  第 {line_no} 行: 事务 {txn} 期望序号 {exp}，实际 {act}")
    else:
        print("序号跳跃: 无")
    if rep.warnings:
        print("其他警告:")
        for line_no, msg in rep.warnings:
            print(f"  第 {line_no} 行: {msg}")

    print("\n========== 重建后的配置 ==========")
    if rep.state:
        for key in sorted(rep.state):
            print(f"{key} = {rep.state[key]}")
    else:
        print("（空）")
    if log.checksum_ok is not True:
        print("\n注意: 校验和未通过，以上配置基于不可信日志，仅供参考。")


# ---------------------------------------------------------------- 入口

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="redo 日志回放与校验工具（纯标准库）")
    ap.add_argument("logfile", nargs="?", help="redo 日志文件路径")
    ap.add_argument("--strict", action="store_true", help="校验和未通过时直接中止，不回放")
    ap.add_argument("--sample", action="store_true", help="生成样例日志到 stdout")
    ap.add_argument("--gap", action="store_true", help="样例中包含序号跳跃（配合 --sample）")
    ap.add_argument("--corrupt", action="store_true", help="样例内容被篡改（配合 --sample）")
    args = ap.parse_args(argv)

    if args.sample:
        sys.stdout.write(build_sample(args.gap, args.corrupt))
        return 0
    if not args.logfile:
        ap.error("需要日志文件路径（或用 --sample 生成样例）")

    with open(args.logfile, "r", encoding="utf-8") as f:
        text = f.read()
    log = parse_log(text)

    if args.strict and log.checksum_ok is not True:
        print(f"[FAIL] {log.checksum_msg}", file=sys.stderr)
        print("--strict 模式：校验未通过，中止回放。", file=sys.stderr)
        return 2

    rep = Replayer()
    for rec in log.records:
        rep.apply(rec)
    print_report(log, rep)
    return 0 if log.checksum_ok is True and not log.parse_errors else 2


if __name__ == "__main__":
    sys.exit(main())
