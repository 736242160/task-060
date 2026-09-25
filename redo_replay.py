#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
redo_replay.py — redo 日志校验与回放工具（纯标准库，单文件）

日志格式（每行一条记录，空白分隔；值可含空格，按前 4 个空白切分）：
    <事务号> <序号> <操作> <键> <值>

  - 操作: SET / DEL / COMMIT / ABORT
  - COMMIT、ABORT 行的键和值用 '-' 占位，例如:  T1 3 COMMIT - -
  - 以 '#' 开头的行是注释，空行忽略
  - 文件尾部应有一行校验行（用 --write-checksum 生成）：
      # CHECKSUM count=<数据行数> crc32=<整体CRC32> lines=<逐行CRC32,逗号分隔>

用法:
    python3 redo_replay.py 日志文件                  校验并回放
    python3 redo_replay.py 日志文件 --apply-uncommitted   强制应用未提交事务
    python3 redo_replay.py 日志文件 --write-checksum      生成/刷新尾部校验行
"""

from __future__ import annotations

import argparse
import sys
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

CHECKSUM_PREFIX = "# CHECKSUM"
VALID_OPS = {"SET", "DEL", "COMMIT", "ABORT"}
DATA_OPS = {"SET", "DEL"}


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #
@dataclass
class Entry:
    line_no: int                       # 在原文件中的行号（1 起）
    txn: str                           # 事务号
    seq: int                           # 事务内序号
    op: str                            # SET / DEL / COMMIT / ABORT
    key: str
    value: Optional[str]
    raw: str                           # 原始行文本


@dataclass
class Issue:
    level: str                         # ERROR / WARN / INFO
    line_no: Optional[int]             # None 表示不针对具体行
    message: str

    def render(self) -> str:
        where = f"第 {self.line_no} 行: " if self.line_no is not None else ""
        return f"[{self.level}] {where}{self.message}"


# --------------------------------------------------------------------------- #
# 校验和
# --------------------------------------------------------------------------- #
def crc32_hex(text: str) -> str:
    return format(zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF, "08x")


def build_checksum_line(data_lines: List[str]) -> str:
    """逐行 CRC32 用于定位首个损坏行；整体 CRC32 用于确认全量一致。"""
    per_line = ",".join(crc32_hex(line) for line in data_lines)
    whole = crc32_hex("\n".join(data_lines))
    return f"{CHECKSUM_PREFIX} count={len(data_lines)} crc32={whole} lines={per_line}"


def parse_checksum_line(line: str) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for field in line[len(CHECKSUM_PREFIX):].split():
        if "=" in field:
            key, val = field.split("=", 1)
            meta[key] = val
    return meta


def verify_checksum(data_lines: List[str], checksum_line: str) -> List[Issue]:
    """逐行比对，定位第一个不对的行号；并检查截断/多余/整体校验。"""
    try:
        meta = parse_checksum_line(checksum_line)
        expected_count = int(meta["count"])
        per_line = meta["lines"].split(",") if meta.get("lines") else []
        expected_whole = meta["crc32"]
    except (KeyError, ValueError):
        return [Issue("ERROR", None, "校验行格式损坏，无法解析")]

    issues: List[Issue] = []
    first_bad: Optional[int] = None

    for i, expected_hash in enumerate(per_line):
        if i >= len(data_lines):
            first_bad = i + 1
            issues.append(Issue("ERROR", first_bad,
                f"日志被截断：校验记录应有 {expected_count} 行数据，"
                f"实际仅 {len(data_lines)} 行，自第 {first_bad} 行起缺失"))
            break
        if crc32_hex(data_lines[i]) != expected_hash:
            first_bad = i + 1
            issues.append(Issue("ERROR", first_bad,
                f"内容与校验和不符，日志自该行起被改动: {data_lines[i]!r}"))
            break

    if first_bad is None and len(data_lines) > expected_count:
        first_bad = expected_count + 1
        issues.append(Issue("ERROR", first_bad,
            f"日志比校验记录多出 {len(data_lines) - expected_count} 行，"
            f"自第 {first_bad} 行起为多余内容"))

    if first_bad is None and crc32_hex("\n".join(data_lines)) != expected_whole:
        issues.append(Issue("ERROR", None,
            "整体校验和不符，但逐行校验一致（校验行本身可能被改动）"))

    return issues


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
def parse_entries(data_lines: List[str]) -> Tuple[List[Entry], List[Issue]]:
    entries: List[Entry] = []
    issues: List[Issue] = []

    for line_no, raw in enumerate(data_lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(None, 4)  # 值保留剩余原文，允许包含空格
        if len(parts) < 3:
            issues.append(Issue("ERROR", line_no,
                f"字段不足（至少需要: 事务号 序号 操作）: {raw!r}"))
            continue

        txn, seq_text, op = parts[0], parts[1], parts[2].upper()
        key = parts[3] if len(parts) > 3 else "-"
        value = parts[4] if len(parts) > 4 else None

        try:
            seq = int(seq_text)
        except ValueError:
            issues.append(Issue("ERROR", line_no, f"序号不是整数: {seq_text!r}"))
            continue

        if op not in VALID_OPS:
            issues.append(Issue("ERROR", line_no, f"未知操作 {op!r}（支持 {sorted(VALID_OPS)}）"))
            continue
        if op in DATA_OPS and key == "-":
            issues.append(Issue("ERROR", line_no, f"{op} 操作缺少键: {raw!r}"))
            continue
        if op == "SET" and value is None:
            issues.append(Issue("ERROR", line_no, f"SET 操作缺少值: {raw!r}"))
            continue

        entries.append(Entry(line_no, txn, seq, op, key, value, raw))

    return entries, issues


# --------------------------------------------------------------------------- #
# 回放
# --------------------------------------------------------------------------- #
def replay(entries: List[Entry], apply_uncommitted: bool
           ) -> Tuple[Dict[str, str], List[Issue], Set[str], Dict[str, List[Entry]]]:
    issues: List[Issue] = []
    txns: Dict[str, List[Entry]] = {}
    for entry in entries:
        txns.setdefault(entry.txn, []).append(entry)

    # 1) 事务内序号连续性检查（允许乱序到达，按日志出现顺序比对 1,2,3,...）
    for txn, ops in txns.items():
        expected = 1
        for entry in ops:
            if entry.seq != expected:
                issues.append(Issue("WARN", entry.line_no,
                    f"事务 {txn} 序号跳跃/缺失：期望序号 {expected}，"
                    f"实际 {entry.seq}（{expected} 与 {entry.seq} 之间可能丢记录）"))
                expected = entry.seq  # 重新对齐，继续检查后续
            expected += 1

    # 2) 只有含 COMMIT 的事务才视为已提交
    committed: Set[str] = set()
    for txn, ops in txns.items():
        if any(e.op == "COMMIT" for e in ops):
            committed.add(txn)

    # 3) 严格按日志文件顺序应用，保证事务交织时结果确定
    config: Dict[str, str] = {}
    for entry in entries:
        if entry.op not in DATA_OPS:
            continue
        is_committed = entry.txn in committed
        if not is_committed and not apply_uncommitted:
            continue
        if not is_committed:
            issues.append(Issue("WARN", entry.line_no,
                f"事务 {entry.txn} 未提交，按 --apply-uncommitted 强制应用"))
        if entry.op == "SET":
            config[entry.key] = entry.value  # type: ignore[assignment]
        else:  # DEL
            if entry.key in config:
                del config[entry.key]
            else:
                issues.append(Issue("INFO", entry.line_no,
                    f"DEL 操作的键 {entry.key!r} 当前不存在，删除为空操作"))

    # 4) 汇总未回放事务
    for txn, ops in txns.items():
        if txn in committed:
            continue
        aborted = any(e.op == "ABORT" for e in ops)
        reason = "已中止（ABORT）" if aborted else "未提交（缺少 COMMIT 标记）"
        n_ops = sum(1 for e in ops if e.op in DATA_OPS)
        line_refs = ",".join(str(e.line_no) for e in ops)
        issues.append(Issue("INFO" if aborted else "WARN", None,
            f"事务 {txn} {reason}，跳过其 {n_ops} 个数据操作（涉及行 {line_refs}）"))

    return config, issues, committed, txns


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def split_checksum(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    """校验行必须是最后一个非空行；其余均视为被校验的数据行（含注释/空行）。"""
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip():
            if lines[i].startswith(CHECKSUM_PREFIX):
                return lines[:i], lines[i]
            break
    return lines, None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="redo 日志校验与回放工具（纯标准库）")
    parser.add_argument("logfile", help="redo 日志文件路径")
    parser.add_argument("--apply-uncommitted", action="store_true",
                        help="回放时也应用未提交事务（默认丢弃）")
    parser.add_argument("--write-checksum", action="store_true",
                        help="重新生成并写回日志尾部的校验行，然后退出")
    args = parser.parse_args(argv)

    try:
        with open(args.logfile, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"无法读取日志文件: {exc}", file=sys.stderr)
        return 1

    lines = text.splitlines()

    if args.write_checksum:
        data_lines = [ln for ln in lines if not ln.startswith(CHECKSUM_PREFIX)]
        checksum_line = build_checksum_line(data_lines)
        with open(args.logfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(data_lines + [checksum_line]) + "\n")
        print("已写入校验行:")
        print(checksum_line)
        return 0

    data_lines, checksum_line = split_checksum(lines)
    has_error = False

    # --- 校验和验证 ---
    print("== 1. 校验和验证 ==")
    if checksum_line is None:
        print("[WARN] 日志尾部缺少校验行，无法验证完整性")
    else:
        checksum_issues = verify_checksum(data_lines, checksum_line)
        if checksum_issues:
            for issue in checksum_issues:
                print(issue.render())
            has_error = True
        else:
            print(f"OK：共 {len(data_lines)} 行，逐行与整体校验均一致")

    # --- 解析 ---
    entries, parse_issues = parse_entries(data_lines)
    print("\n== 2. 日志解析 ==")
    if parse_issues:
        for issue in parse_issues:
            print(issue.render())
        has_error = True
    print(f"有效记录 {len(entries)} 条，问题记录 {len(parse_issues)} 条")

    # --- 回放 ---
    config, replay_issues, committed, txns = replay(entries, args.apply_uncommitted)
    print("\n== 3. 回放报告 ==")
    skipped = len(txns) - len(committed)
    print(f"事务总数 {len(txns)}；已提交 {len(committed)}；"
          f"未提交/中止 {skipped}；仅已提交事务的数据操作被应用")
    for issue in replay_issues:
        print(issue.render())

    # --- 重建状态 ---
    print("\n== 4. 重建后的配置状态 ==")
    if has_error:
        print("（注意：存在校验/解析错误，以下结果可能与真实状态不一致）")
    if config:
        width = max(len(k) for k in config)
        for key in sorted(config):
            print(f"  {key.ljust(width)} = {config[key]}")
    else:
        print("  （空）")

    return 1 if has_error else 0


if __name__ == "__main__":
    sys.exit(main())
