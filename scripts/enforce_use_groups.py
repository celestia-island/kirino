#!/usr/bin/env python3
"""Group the `use` statements of every Rust file; leave rustfmt to own the shape.

Authority split (2026-11-24 ruling; this table is the contract)
---------------------------------------------------------------
Two tools touch these blocks, so each property gets exactly one owner:

| property                                            | owner    |
| --------------------------------------------------- | -------- |
| which *statement* an item lives in (== grouping)     | script   |
| the order of the statements, section by section      | script   |
| the members of a statement, compared exactly          | script   |
| the members' spelling: `pub`/`pub(crate)`, `as` alias | script   |
| the order of items *inside* one brace block          | rustfmt  |
| single-line vs multi-line, indent, trailing comma    | rustfmt  |

This is deliberately *not* "the script owns every byte of the layout". rustfmt
normalises in-block item order on its own (`rustfmt.toml` sets `reorder_imports`, and
rustfmt sorts the items inside one group regardless), as measured on the pinned
toolchain:

    use std::{sync::Arc, collections::HashMap};      ->  use std::{collections::HashMap, sync::Arc};
    use crate::rbac::{traits::Permission, prelude::*}; ->  use crate::rbac::{prelude::*, traits::Permission};

Claiming that order would mean the two tools disagree on the same bytes forever
(the old failure mode, only now *inside* the braces). It is therefore assigned to
rustfmt, and this tool compares — and only ever rewrites — the parts rustfmt leaves
alone. "Order" below always means *between statements*; the order inside a block is
rustfmt's business.

Convergence is a consequence rather than a hope: an import block whose statements
are grouped correctly and whose members are complete *is already correct* — whatever
rustfmt did to the item order inside its braces and however many lines it used. The
script leaves it byte-for-byte alone, so `fmt` -> `check` settles on the first pass
and nothing oscillates between the two tools.

Grouping policy
---------------
1. Three sections, in this order:

   1. shared utility crates (`std`, `anyhow`, `serde`, `tokio`, ...);
   2. domain-specific external crates (e.g. `serialport`, `rmodbus`, `ratatui`);
   3. workspace / internal crates (`crate::`, `self::`, `super::`, `philia`, any
      crate name declared by a `Cargo.toml` under the repository, and — the
      "underscore rule" — any crate whose name starts with `_`).

2. Inside a section, statements that share a crate are merged into one block so that
   the grouping — not the line shape — decides what happens to them
   (`use std::sync::Arc;` + `use std::collections::HashMap;` ->
   `use std::{collections::HashMap, sync::Arc};`; the item order inside the block is
   rustfmt's, and it re-sorts this exact example on its next pass).

3. A single blank line separates the sections and follows the final section, except
   that a file emitting bare attributes is not required to keep the trailing blank
   line (see "Attributes" below).

4. In `mod.rs`, `lib.rs` and `main.rs`, every `mod` declaration precedes the first
   `use` block.

Attributes and doc comments travel with their statement, which is why the *merged*
blocks are described as "one statement per crate": attributes live on the statement,
so two statements that carry them cannot be folded together.

Since crate-level `#![...]` inner attributes are leading trivia rather than a block
prefix, the blank line after the last section is not enforced on a file that emits
bare attributes: a leading `#[` in the import region makes a trailing blank line
change what rustfmt considers part of the block. Doc comments always feed such a
file that separator back.

What counts as a deviation
--------------------------
Per section, the expectation is the sequence of statements the renderer emits
(statements sorted, crates merged, `pub(crate)`/`pub` kept, `self` leading a block)
and, for each of them, the **exact multiset of members it must import**
(`a::{b::{c, d}, e}` -> `a::b::c`, `a::b::d`, `a::e`, `self` folded away, a leading
`::` dropped as spelling). A section passes when the sequence is that same length,
each statement has the same members in the same *set*, and the statements sit in the
same order. Any regrouping — a member missing, an extra member present, a member
standing in a different statement (a block grown, split, or folded into its
neighbour) — is a deviation and is reported; the comparison is lossless, so a moved
member can never hide inside a re-rendered block. Item order *inside* one block is not
compared (rustfmt owns it); in particular a one-member block never changes under this
comparison, so its in-block data is safe from the loop above. The deviation is
reported at the 1-based line of the first statement that differs, which makes the
direction of a real misordering visible in the diff.

Modes (run from the repository root; every `*.rs` under the CWD is scanned,
`target/` excluded, `#[path]`-attached files excluded as they are not module roots):

- default (no flag): rewrite the files whose *grouping* deviates, then run
  `cargo fmt` (which owns the shape). A converged tree passes through byte-identical.
- ``--check``: report every file whose *grouping* deviates as
  ``<path>:<first deviating line>`` and write nothing — neither sources nor
  `cargo fmt`. Shape is not a deviation, so a rustfmt-expanded block passes.
  This is the `just ci` gate.
- ``--test``: run the built-in classification, grouping and convergence self-tests.

Exit codes: ``0`` = clean / written back successfully, ``1`` = ``--check`` found
grouping deviations (the legacy fatal-error path also exits ``1``), ``2`` = usage error.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

GROUP1_CRATES = {
    "std",
    "core",
    "alloc",
    "anyhow",
    "serde",
    "serde_json",
    "serde_yaml",
    "serde_repr",
    "serde_with",
    "serde_bytes",
    "serde_path_to_error",
    "serde_cbor",
    "serde_urlencoded",
    "serde_json_path",
    "toml",
    "ron",
    "regex",
    "lazy_static",
    "once_cell",
    "tokio",
    "futures",
    "async_std",
    "chrono",
    "log",
    "uuid",
    "rand",
    "base64",
    "bytes",
    "cfg_if",
    "parking_lot",
    "url",
    "rayon",
    "snap",
    "strum",
}

USE_RE = re.compile(r"^\s*(pub\s+)?use\b")
MOD_RE = re.compile(r"^\s*(pub\s+)?mod\b")
ATTR_RE = re.compile(r"^\s*#\[")
COMMENT_RE = re.compile(r"^\s*//")
BLOCK_COMMENT_START_RE = re.compile(r"^\s*/\*")


WORKSPACE_CRATES: set[str] = set()

SCRIPT_PATH = Path(__file__).resolve()


@dataclass
class UseStatement:
    lines: List[str]
    path: Optional[str]
    is_pub: bool
    group: int
    simple_prefix: Optional[str]
    simple_leaf: Optional[str]
    has_attrs: bool
    # For more general merging by top-level crate, store base and remainder
    merge_base: Optional[str]
    merge_remainder: Optional[str]

    def text(self) -> str:
        return "".join(self.lines)


@dataclass
class Statement:
    kind: str  # "use" or "mod"
    lines: List[str]
    use_stmt: Optional[UseStatement] = None
    # 1-based line where the statement's code starts (after any attribute lines).
    line_number: int = 0


def load_workspace_crates(root: Path) -> set[str]:
    crates: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        if "target" in dirnames:
            dirnames.remove("target")
        if "Cargo.toml" not in filenames:
            continue
        path = Path(dirpath) / "Cargo.toml"
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
        except Exception:
            continue
        package = data.get("package")
        if package and "name" in package:
            crates.add(package["name"])
    return crates


def strip_line_comments(line: str) -> str:
    """剥离行内注释，处理字符串内的 // 不被误剥离的情况。

    简化处理：假设 use 语句中不包含字符串字面量。
    特殊处理：如果重要语法字符（;, }, {）在注释之后，需要保留它们。
    """
    idx = line.find("//")
    if idx == -1:
        return line

    before_comment = line[:idx]
    after_comment = line[idx:]

    # 收集需要保留的语法字符
    suffix = ""

    # 检查 } 是否在注释部分但不在 before_comment 中平衡
    # 统计 before_comment 中的大括号
    open_braces = before_comment.count("{")
    close_braces = before_comment.count("}")

    # 如果注释后有 }，并且 before_comment 中 { 多于 }，则需要保留 }
    if "}" in after_comment and open_braces > close_braces:
        needed_closes = open_braces - close_braces
        for _ in range(needed_closes):
            suffix += "}"

    # 如果分号在注释部分，需要把分号加回来
    if ";" in after_comment:
        suffix += ";"

    result = before_comment.rstrip()
    if suffix:
        result += suffix

    return result


def extract_use_path(lines: Sequence[str]) -> Optional[str]:
    # 先剥离每行的行内注释，然后再拼接
    cleaned_lines = []
    for line in lines:
        if ATTR_RE.match(line):
            continue
        cleaned = strip_line_comments(line).strip()
        if cleaned:
            cleaned_lines.append(cleaned)
    joined = " ".join(cleaned_lines)
    match = re.search(r"\buse\s+([^;]+);", joined)
    return match.group(1).strip() if match else None


def extract_base_crate(path: str) -> str:
    token = path.strip()
    if token.startswith("pub "):
        token = token[4:].strip()
    if token.startswith("use "):
        token = token[4:].strip()
    token = token.lstrip(":").strip()
    match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)', token)
    if match:
        return match.group(1)
    return ""


def classify_use(path: Optional[str], workspace_crates: set[str]) -> int:
    if not path:
        return 2
    base = extract_base_crate(path)
    if not base:
        return 2
    if base in ("crate", "self", "super"):
        return 3
    # Ensure `philia` is always treated as an internal/workspace crate (group 3)
    if base == "philia":
        return 3
    if base.startswith("_"):
        return 3
    if base in workspace_crates:
        return 3
    if base in GROUP1_CRATES:
        return 1
    return 2


def compute_simple_components(path: Optional[str], has_attrs: bool) -> Tuple[Optional[str], Optional[str]]:
    if has_attrs or not path:
        return None, None
    token = path.strip()
    if any(ch in token for ch in "{}*"):
        return None, None
    if " as " in token:
        return None, None
    if token.endswith(":"):
        return None, None
    parts = token.split("::")
    if len(parts) < 2:
        return None, None
    prefix = "::".join(parts[:-1])
    leaf = parts[-1].strip()
    if not prefix or not leaf:
        return None, None
    return prefix, leaf


def compute_merge_components(path: Optional[str], has_attrs: bool) -> Tuple[Optional[str], Optional[str]]:
    if has_attrs or not path:
        return None, None
    base = extract_base_crate(path)
    if not base:
        return None, None
    token = path.strip()
    if token.startswith("pub "):
        token = token[4:].strip()
    if token.startswith("use "):
        token = token[4:].strip()
    token = token.lstrip(":").strip()
    if token.startswith(base):
        if len(token) > len(base) and token[len(base):len(base)+2] == "::":
            remainder = token[len(base)+2:]
            return base, remainder
        elif len(token) == len(base):
            return base, ""
    return None, None


def append_blank_line(buf: List[str]) -> None:
    if not buf:
        return
    if buf[-1].strip():
        buf.append("\n")


def attribute_is_self_contained(line: str) -> bool:
    """Does a single `#[...]` line close the brackets it opens?

    Attributes are attached to the statement that follows them, so a run of them is a
    prefix. A *multi-line* attribute (`#[cfg(all(feature = "a", feature = "b"))]` split
    across lines) is not: its trailing `)]` would be read as the head of a statement
    that does not exist. Such a run ends the import region instead of being glued to
    whatever comes next.
    """
    code = line.split("//")[0]
    return code.count("[") == code.count("]")


def collect_statement(lines: List[str], idx: int) -> Tuple[Optional[Statement], int]:
    attrs: List[str] = []
    cur = idx
    while cur < len(lines) and ATTR_RE.match(lines[cur]):
        attrs.append(lines[cur])
        cur += 1
    if cur >= len(lines):
        return None, idx
    if attrs and not all(attribute_is_self_contained(line) for line in attrs):
        return None, idx
    line = lines[cur]
    if USE_RE.match(line):
        stmt_lines = attrs + [line]
        cur += 1
        balance = code_brace_balance(line)
        semicolon_found = ";" in strip_line_comments(line) and balance <= 0
        while not semicolon_found and cur < len(lines):
            stmt_lines.append(lines[cur])
            balance += code_brace_balance(lines[cur])
            if ";" in strip_line_comments(lines[cur]) and balance <= 0:
                semicolon_found = True
            cur += 1
        use_stmt = build_use_statement(stmt_lines)
        attr_lines = sum(1 for attr in attrs)
        return Statement("use", stmt_lines, use_stmt, idx + attr_lines + 1), cur
    if MOD_RE.match(line):
        stmt_lines = attrs + [line]
        cur += 1
        attr_lines = sum(1 for attr in attrs)
        return Statement("mod", stmt_lines, None, idx + attr_lines + 1), cur
    return None, idx


def code_brace_balance(line: str) -> int:
    """Net `{` - `}` of a line's code, counting comments out.

    `use` paths never contain string or char literals, so only line comments matter.
    Counting the braces inside a comment would let a `// { note` line swallow the rest
    of the file into a single "statement", and counting them only in `code` is exactly
    what `strip_line_comments` returns for a `use` line.
    """
    code = strip_line_comments(line)
    return code.count("{") - code.count("}")


def build_use_statement(lines: List[str]) -> UseStatement:
    code_lines = [line for line in lines if not ATTR_RE.match(line)]
    path = extract_use_path(lines)
    is_pub = bool(code_lines and code_lines[0].lstrip().startswith("pub "))
    has_attrs = any(ATTR_RE.match(line) for line in lines)
    prefix, leaf = compute_simple_components(path, has_attrs)
    merge_base, merge_remainder = compute_merge_components(path, has_attrs)
    group = classify_use(path, WORKSPACE_CRATES)
    return UseStatement(lines, path, is_pub, group, prefix, leaf, has_attrs, merge_base, merge_remainder)


def flush_simple(pending: OrderedDict[Tuple[bool, str], List[str]], output: List[str]) -> None:
    for (is_pub, prefix), leaves in pending.items():
        unique_leaves: List[str] = []
        seen = set()
        for leaf in leaves:
            if leaf not in seen:
                unique_leaves.append(leaf)
                seen.add(leaf)
        if not unique_leaves:
            continue
        if len(unique_leaves) == 1:
            line = f"{'pub ' if is_pub else ''}use {prefix}::{unique_leaves[0]};\n"
        else:
            inner = ", ".join(unique_leaves)
            line = f"{'pub ' if is_pub else ''}use {prefix}::{{{inner}}};\n"
        output.append(line)
    pending.clear()


def normalize_remainder_items(remainder: str) -> List[str]:
    remainder = remainder.strip()
    if remainder.startswith("{") and remainder.endswith("}"):
        inner = remainder[1:-1]
        parts: List[str] = []
        cur: List[str] = []
        depth = 0
        for ch in inner:
            if ch == '{':
                depth += 1
                cur.append(ch)
            elif ch == '}':
                depth -= 1
                cur.append(ch)
            elif ch == ',' and depth == 0:
                part = ''.join(cur).strip()
                if part:
                    parts.append(part)
                cur = []
            else:
                cur.append(ch)
        last = ''.join(cur).strip()
        if last:
            parts.append(last)
        return parts
    if remainder == "":
        return []
    return [remainder]


def find_matching_brace(s: str, start: int) -> int:
    """找到与 start 位置的 '{' 匹配的 '}' 的位置。

    返回 '}' 的索引，如果没找到则返回 -1。
    """
    if start >= len(s) or s[start] != '{':
        return -1
    depth = 0
    for i in range(start, len(s)):
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1


def expand_braced_item(item: str) -> List[str]:
    """递归展开单个包含大括号的路径项。

    例如: 'a::b::{C, D::{E, F}}'
    变成: ['a::b::C', 'a::b::D::E', 'a::b::D::F']
    """
    if item == "":
        return [""]

    # 查找最外层的大括号
    brace_start = item.find('{')
    if brace_start == -1:
        return [item]

    # 确保大括号前面有 ::
    if brace_start < 2 or item[brace_start-2:brace_start] != "::":
        return [item]

    brace_end = find_matching_brace(item, brace_start)
    if brace_end == -1:
        return [item]

    # 提取前缀和大括号内容
    prefix = item[:brace_start-2]  # 去掉 "::"
    braced_content = item[brace_start:brace_end+1]
    suffix = item[brace_end+1:]  # 大括号后的内容（通常为空）

    # 解析大括号内的内容
    inner_items = normalize_remainder_items(braced_content)

    expanded: List[str] = []
    for inner in inner_items:
        if inner == "":
            # self 的情况
            new_item = prefix + suffix
        else:
            new_item = f"{prefix}::{inner}{suffix}"
        # 递归展开（处理嵌套大括号）
        expanded.extend(expand_braced_item(new_item))

    return expanded


def expand_braced_items(items: List[str]) -> List[str]:
    """展开包含大括号的路径项。

    例如: ['nodes::{A, B}', 'nodes::status::C']
    变成: ['nodes::A', 'nodes::B', 'nodes::status::C']

    支持嵌套大括号:
    例如: ['a::{B, C::{D, E}}']
    变成: ['a::B', 'a::C::D', 'a::C::E']

    这确保了嵌套导入能被正确地合并到导入树中。
    """
    expanded: List[str] = []
    for item in items:
        expanded.extend(expand_braced_item(item))
    return expanded


def build_import_tree(items: List[str]) -> dict:
    # 首先展开所有包含大括号的项
    expanded_items = expand_braced_items(items)
    tree: dict = {}
    for item in expanded_items:
        if item == "":
            tree[""] = {}
            continue
        parts = item.split("::")
        current = tree
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]
    return tree


def format_import_tree(tree: dict, indent: int = 0) -> str:
    if not tree:
        return ""
    has_self = "" in tree
    keys = sorted([k for k in tree.keys() if k != ""])
    if not keys:
        return ""
    if len(keys) == 1 and not tree[keys[0]] and not has_self:
        return keys[0]
    parts: List[str] = []
    if has_self:
        parts.append("self")
    for key in keys:
        subtree = tree[key]
        if not subtree:
            parts.append(key)
        else:
            child_str = format_import_tree(subtree)
            if child_str:
                parts.append(f"{key}::{child_str}")
            else:
                parts.append(key)
    if len(parts) == 1 and not has_self:
        return parts[0]
    return "{" + ", ".join(parts) + "}"


def find_common_prefix(paths: List[str]) -> str:
    if not paths:
        return ""
    if len(paths) == 1:
        if "::" in paths[0]:
            return "::".join(paths[0].split("::")[:-1])
        return ""
    all_parts = [p.split("::") if p else [] for p in paths]
    if not all_parts or not all(parts for parts in all_parts):
        return ""
    prefix_parts: List[str] = []
    for i in range(min(len(parts) for parts in all_parts)):
        part = all_parts[0][i]
        if all(parts[i] == part for parts in all_parts):
            prefix_parts.append(part)
        else:
            break
    return "::".join(prefix_parts)


def render_group(statements: List[UseStatement]) -> List[str]:
    if not statements:
        return []
    output: List[str] = []
    pending: OrderedDict[Tuple[bool, str], List[str]] = OrderedDict()
    for stmt in statements:
        if stmt.merge_base and stmt.merge_remainder is not None and not stmt.has_attrs:
            key = (stmt.is_pub, stmt.merge_base)
            if key not in pending:
                pending[key] = []
            items = normalize_remainder_items(stmt.merge_remainder)
            if items:
                pending[key].extend(items)
            else:
                pending[key].append("")
            continue
        flush_merged_groups(pending, output)
        output.extend(stmt.lines)
    flush_merged_groups(pending, output)
    return output


def flush_merged_groups(pending: OrderedDict[Tuple[bool, str], List[str]], output: List[str]) -> None:
    for (is_pub, base), items in pending.items():
        if not items:
            continue
        common_prefix = find_common_prefix(items)
        if common_prefix:
            new_base = f"{base}::{common_prefix}"
            new_items: List[str] = []
            for item in items:
                if item == "":
                    new_items.append("")
                elif item == common_prefix:
                    new_items.append("")
                elif item.startswith(common_prefix + "::"):
                    new_items.append(item[len(common_prefix) + 2:])
                else:
                    new_items.append(item)
            tree = build_import_tree(new_items)
            formatted = format_import_tree(tree)
            if formatted:
                line = f"{'pub ' if is_pub else ''}use {new_base}::{formatted};\n"
            else:
                line = f"{'pub ' if is_pub else ''}use {new_base};\n"
        else:
            tree = build_import_tree(items)
            formatted = format_import_tree(tree)
            if formatted:
                line = f"{'pub ' if is_pub else ''}use {base}::{formatted};\n"
            else:
                line = f"{'pub ' if is_pub else ''}use {base};\n"
        output.append(line)
    pending.clear()


def render_use_section(use_statements: List[UseStatement]) -> List[str]:
    grouped: dict[int, List[UseStatement]] = {1: [], 2: [], 3: []}
    for stmt in use_statements:
        grouped[stmt.group].append(stmt)
    rendered: List[str] = []
    for group in (1, 2, 3):
        block = render_group(grouped[group])
        if not block:
            continue
        if rendered and rendered[-1].strip():
            rendered.append("\n")
        rendered.extend(block)
    if rendered and rendered[-1].strip():
        rendered.append("\n")
    return rendered


def split_top_level_items(inner: str) -> List[str]:
    """Split the inside of a `{...}` group on the commas that are not nested."""
    parts: List[str] = []
    cur: List[str] = []
    depth = 0
    for ch in inner:
        if ch == '{':
            depth += 1
            cur.append(ch)
        elif ch == '}':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append(''.join(cur))
    return [part.strip() for part in parts if part.strip()]


def statement_members(path_text: str) -> Tuple[str, ...]:
    """Every member this `use` statement imports, as a sorted (unordered) tuple.

    `a::{b::{c, d}, e}` yields `a::b::c`, `a::b::d`, `a::e`; `self` inside a group names
    the prefix it sits in and so adds no member of its own (`a::{self, b}` -> `a`,
    `a::b`); a leading `::` (a 2018-edition absolute path) is spelling, not membership.

    The tuple is sorted because rustfmt — not this tool — owns the order of items inside
    a block: `std::{sync::Arc, collections::HashMap}` and
    `std::{collections::HashMap, sync::Arc}` are the *same* grouping and only the
    members count. Comparison is set-based for that reason alone; it stays lossless —
    a member added, dropped, or moved into another statement changes this tuple, so no
    regrouping can slip through.
    """
    text = path_text.strip()
    text = re.sub(r"^(?:pub(?:\([^)]*\))?\s+)?use\s+", "", text)
    text = text.strip().lstrip(":")
    members: List[str] = []

    def walk(segment: str, prefix: str) -> None:
        brace = segment.find('{')
        if brace == -1:
            item = segment.strip()
            if not item:
                return
            if item == "self":
                if prefix:
                    members.append(prefix)
                return
            members.append(f"{prefix}::{item}" if prefix else item)
            return
        head = segment[:brace].strip()
        if head.endswith("::"):
            head = head[:-2].rstrip()
        group_prefix = f"{prefix}::{head}" if (prefix and head) else (head or prefix)
        close = find_matching_brace(segment, brace)
        if close == -1:
            members.append(segment.strip())
            return
        for sub in split_top_level_items(segment[brace + 1:close]):
            walk(sub, group_prefix)
        remainder = segment[close + 1:].strip()
        if remainder:
            members.append(f"{group_prefix}::{remainder}" if group_prefix else remainder)

    walk(text, "")
    return tuple(sorted(members))


def statements_of(rendered: List[str]) -> List[UseStatement]:
    """Parse a rendered block back into `UseStatement`s, one per emitted statement."""
    found: List[UseStatement] = []
    cur = 0
    while cur < len(rendered):
        if rendered[cur].strip() == "":
            cur += 1
            continue
        stmt, next_cur = collect_statement(rendered, cur)
        if stmt is None or next_cur <= cur:
            break
        if stmt.kind == "use" and stmt.use_stmt is not None:
            found.append(stmt.use_stmt)
        cur = next_cur
    return found


def section_signature(statements: Sequence[UseStatement]) -> Tuple[Tuple[str, ...], ...]:
    """One entry per statement: the members that statement must hold."""
    return tuple(statement_members(stmt.path or "") for stmt in statements)


def build_plan(use_statements: List[UseStatement]) -> Tuple[Tuple[Tuple[str, ...], ...], ...]:
    """The expected grouping: one member signature per statement, section by section."""
    grouped: Dict[int, List[UseStatement]] = {1: [], 2: [], 3: []}
    for stmt in use_statements:
        grouped[stmt.group].append(stmt)
    plan: List[Tuple[Tuple[str, ...], ...]] = []
    for group in (1, 2, 3):
        block = render_group(grouped[group])
        if not block:
            continue
        plan.append(section_signature(statements_of(block)))
    return tuple(plan)


def current_grouping(use_statements: List[UseStatement]) -> Tuple[Tuple[Tuple[str, ...], ...], ...]:
    """The grouping the file actually has: sections in file order, statements in order."""
    sections: List[List[UseStatement]] = []
    current: List[UseStatement] = []
    current_group: Optional[int] = None
    for stmt in use_statements:
        if current and stmt.group == current_group:
            current.append(stmt)
            continue
        if current:
            sections.append(current)
        current = [stmt]
        current_group = stmt.group
    if current:
        sections.append(current)
    return tuple(section_signature(section) for section in sections)


def find_use_block(lines: List[str]) -> Tuple[List[str], List[Statement], int]:
    """Split a file into its leading trivia, its import region, and the rest."""
    idx = 0
    prefix: List[str] = []
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped == "" or COMMENT_RE.match(lines[idx]) or BLOCK_COMMENT_START_RE.match(lines[idx]):
            prefix.append(lines[idx])
            idx += 1
            continue
        if lines[idx].startswith("#!"):
            prefix.append(lines[idx])
            idx += 1
            continue
        if ATTR_RE.match(lines[idx]):
            break
        if USE_RE.match(lines[idx]) or MOD_RE.match(lines[idx]):
            break
        return [], [], len(lines)
    statements: List[Statement] = []
    cur = idx
    while cur < len(lines):
        stmt, next_idx = collect_statement(lines, cur)
        if stmt is None:
            break
        statements.append(stmt)
        cur = next_idx
        while cur < len(lines) and lines[cur].strip() == "":
            cur += 1
    return prefix, statements, cur


def render_use_block(prefix: List[str], statements: List[Statement], suffix: List[str],
                     require_mod_first: bool) -> List[str]:
    use_section = render_use_section(
        [stmt.use_stmt for stmt in statements if stmt.kind == "use" and stmt.use_stmt])
    new_lines: List[str] = []
    new_lines.extend(prefix)
    if require_mod_first:
        mods = [stmt.lines for stmt in statements if stmt.kind == "mod"]
        for mod_lines in mods:
            new_lines.extend(mod_lines)
        if mods:
            append_blank_line(new_lines)
        new_lines.extend(use_section)
    else:
        others_written = False
        for stmt in statements:
            if stmt.kind == "use":
                continue
            new_lines.extend(stmt.lines)
            others_written = True
        if others_written:
            append_blank_line(new_lines)
        new_lines.extend(use_section)
    new_lines.extend(suffix)
    if new_lines and not new_lines[-1].endswith("\n"):
        new_lines[-1] += "\n"
    return new_lines


@dataclass
class FileStatus:
    """What the scan learned about one file, for both modes to consume."""

    path: Path
    first_line: int = 0

    @property
    def converged(self) -> bool:
        return self.first_line == 0


def inspect_file(path: Path) -> Optional[FileStatus]:
    """Grouping status of one file; `None` when it has no import block to police."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    prefix, statements, cur = find_use_block(lines)
    use_statements = [
        stmt.use_stmt for stmt in statements if stmt.kind == "use" and stmt.use_stmt]
    if not use_statements:
        return None
    if current_grouping(use_statements) == build_plan(use_statements):
        return FileStatus(path)
    return FileStatus(path, _first_deviation_line(statements, use_statements))


def _first_deviation_line(statements: List[Statement], use_statements: List[UseStatement]) -> int:
    """1-based line of the first statement whose grouping is wrong (1 when unknown).

    The file is walked section by section: as soon as a section's signature differs from
    the expected section's, the first statement of that section is the culprit. That is
    enough precision to find the block in a diff; the grouping itself is the thing
    being enforced, not a character-perfect position.
    """
    expected = build_plan(use_statements)
    actual = current_grouping(use_statements)
    consumed = 0
    for section_index, section in enumerate(actual):
        wanted = expected[section_index] if section_index < len(expected) else ()
        for stmt_index, signature in enumerate(section):
            if stmt_index >= len(wanted) or wanted[stmt_index] != signature:
                return _statement_line(statements, consumed + stmt_index)
        consumed += len(section)
    if len(actual) < len(expected):
        return _statement_line(statements, consumed)
    return _statement_line(statements, 0)


def _statement_line(statements: List[Statement], use_index: int) -> int:
    """The 1-based line where the `use_index`-th `use` statement starts (1 if out of range)."""
    seen = 0
    for stmt in statements:
        if stmt.kind != "use":
            continue
        if seen == use_index:
            return stmt.line_number
        seen += 1
    return 1


def process_file(path: Path) -> Optional[str]:
    """The rewritten text when this file's grouping deviates; `None` when it converges."""
    status = inspect_file(path)
    if status is None or status.converged:
        return None
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    prefix, statements, cur = find_use_block(lines)
    new_text = "".join(render_use_block(
        prefix, statements, lines[cur:], path.name in {"mod.rs", "lib.rs", "main.rs"}))
    return new_text


def iter_rust_files() -> List[Path]:
    """Every Rust source file of the workspace rooted at the CWD.

    `target/` holds build output; `#[path = "..."]`-attached files are pulled in by a
    module rather than being module roots, so their import block is not the file's to
    own.
    """
    files: List[Path] = []
    for path in sorted(Path.cwd().rglob("*.rs")):
        if "target" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            files.append(path)
            continue
        if '#[path' in text or '#[path =' in text:
            continue
        files.append(path)
    return files


@dataclass
class Deviation:
    path: Path
    first_line: int


def main(check: bool = False) -> int:
    mode = "--check" if check else "write"
    print("Starting use statement enforcement...")
    print(f"Working directory: {Path.cwd()}")
    print(f"Python version: {sys.version}")
    print(f"Mode: {mode}")
    changed: List[str] = []
    deviations: List[Deviation] = []
    total_files = 0
    path = Path(".")
    try:
        for path in iter_rust_files():
            total_files += 1
            status = inspect_file(path)
            if status is None or status.converged:
                continue
            if check:
                deviations.append(Deviation(path, status.first_line))
                continue
            new_text = process_file(path)
            if new_text is not None:
                path.write_text(new_text, encoding="utf-8")
                changed.append(str(path))
    except Exception as e:
        print(f"Error processing {path}: {e}")
        import traceback
        traceback.print_exc()
        return 1
    print(f"Processed {total_files} Rust files")
    if check:
        print(f"Deviating files: {len(deviations)}")
        for deviation in deviations:
            print(f"{deviation.path}:{deviation.first_line}")
        if deviations:
            print(
                f"`--check` found {len(deviations)} file(s) whose `use` groupings are wrong; "
                "run `just fmt` (or scripts/enforce_use_groups.py without --check) to fix. "
                "Line shape and item order inside a block are rustfmt's and are not counted."
            )
            return 1
        print("All Rust files have the expected use statement grouping")
        return 0
    print(f"Updated {len(changed)} files")
    for item in changed:
        print(item)
    try:
        if shutil.which("cargo"):
            print("Running cargo fmt...")
            result = subprocess.run(
                ["cargo", "fmt"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"cargo fmt exit code: {result.returncode}")
                if result.stderr:
                    print(f"cargo fmt stderr: {result.stderr}")
        else:
            print("cargo not found in PATH; skipping cargo fmt")
    except Exception as e:
        print(f"Failed to run cargo fmt: {e}")
    print("Use statement enforcement completed successfully")
    return 0


def test_underscore_classification() -> bool:
    test_cases = [
        ("_client_functions_3_1::something", 3, "underscore with module path"),
        ("_client_bootstrap_3_1", 3, "underscore simple import"),
        ("_main::run", 3, "underscore _main prefix"),
        ("_utils::helper", 3, "underscore _utils prefix"),
        ("use _client_functions_3_1::init", 3, "with use keyword"),
        ("pub use _utils::setup", 3, "with pub use keywords"),
        ("std::collections", 1, "std library"),
        ("anyhow::Result", 1, "anyhow utility"),
        ("tokio::spawn", 1, "tokio runtime"),
        ("crate::module", 3, "crate prefix"),
        ("self::item", 3, "self prefix"),
        ("super::parent", 3, "super prefix"),
        ("serialport::SerialPort", 2, "serialport external"),
        ("rmodbus::ModbusContext", 2, "rmodbus external"),
    ]
    workspace_crates: set[str] = set()
    all_passed = True
    print("\n" + "="*80)
    print("UNDERSCORE-PREFIXED CRATE CLASSIFICATION TEST")
    print("="*80)
    print(f"\n{'Test Case':<50} | {'Expected':<10} | {'Actual':<10} | Status")
    print("-"*80)
    group_names = {1: "std/util", 2: "external", 3: "internal"}
    for test_input, expected_group, description in test_cases:
        actual_group = classify_use(test_input, workspace_crates)
        passed = actual_group == expected_group
        status = "PASS" if passed else "FAIL"
        expected_name = group_names[expected_group]
        actual_name = group_names[actual_group]
        print(f"{description:<50} | {expected_name:<10} | {actual_name:<10} | {status}")
        if not passed:
            all_passed = False
            base = extract_base_crate(test_input)
            print(f"  -> Input: '{test_input}'")
            print(f"  -> Base crate: '{base}'")
    print("-"*80)
    if all_passed:
        print("\nAll classification tests PASSED!")
        print("\nKey improvements verified:")
        print("  + All underscore-prefixed crates classified as internal (group 3)")
        print("  + Standard library crates correctly in group 1")
        print("  + External domain-specific crates in group 2")
        print("  + Explicit workspace prefixes (crate::, self::, super::) in group 3")
    else:
        print("\nSome tests FAILED!")
    print("="*80 + "\n")
    return all_passed


# --- self-test fixtures ---------------------------------------------------------

EXPANDED_FIXTURE = """\
//! Fixture module: rustfmt already expanded the blocks, and the grouping is right.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use serialport::SerialPort;

use crate::{
    database::memory::InMemoryUserDatabase,
    rbac::permission::Permission,
};

pub fn run() {}
"""

# Same grouping, but the item order inside two brace blocks is the reverse of what
# rustfmt would produce, and the blocks are on single lines. Accepting this shape is
# the whole point of the grouping split: in-block order is rustfmt's to settle.
REVERSED_INBLOCK_FIXTURE = """\
//! Fixture module: correct grouping, rustfmt's in-block sorting not yet applied.

use std::{sync::{Arc, atomic::{Ordering, AtomicU64}}, collections::HashMap};

use serialport::SerialPort;

use crate::{rbac::permission::Permission, database::memory::InMemoryUserDatabase};

pub fn run() {}
"""

# Grouping deviation: `serialport` (group 2) stands before `std` (group 1).
WRONG_GROUP_ORDER_FIXTURE = """\
//! Fixture module: sections out of order.

use serialport::SerialPort;
use std::sync::Arc;

use crate::module::Thing;
"""

# Grouping deviation inside one crate: `std::sync::Arc` and `std::collections::HashMap`
# are two statements where the layout wants them merged into one block.
UNMERGED_CRATE_FIXTURE = """\
//! Fixture module: one crate split across statements.

use std::sync::Arc;
use std::collections::HashMap;

pub fn run() {}
"""

# Grouping deviation: `std` is spread over two statements where the layout wants one
# merged block — a member standing in a different statement from its crate-mates.
MEMBER_IN_WRONG_STATEMENT_FIXTURE = """\
//! Fixture module: one crate split across statements.

use std::collections::HashMap;
use std::sync::Arc;

pub fn run() {}
"""

# Grouping deviation: `std::sync::Arc` is imported twice, so the grouped shape holds one
# member too many. This is the sharpest test of the comparison being list-shaped: both
# statements hold a legal `Arc`, and only counting members per statement exposes it.
DUPLICATE_MEMBER_FIXTURE = """\
//! Fixture module: the same member twice.

use std::sync::Arc;
use std::sync::Arc;

pub fn run() {}
"""

# Should converge once written back: single statement per crate, items grouped.
CLEAN_FIXTURE = """\
//! Fixture module with an already-canonical grouping.

use std::{collections::HashMap, sync::Arc};

use serialport::SerialPort;

use crate::module::Thing;

"""


def _write_fixture(root: Path, name: str, text: str) -> Path:
    path = root / "src" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run_script(cwd: Path, *args: str) -> Tuple[int, str]:
    """Run this script as a subprocess from `cwd`."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        cwd=str(cwd), capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def _report(description: str, ok: bool, detail: str = "") -> bool:
    print(f"{description:<58} | {'PASS' if ok else 'FAIL'}" + (f" | {detail}" if detail else ""))
    return ok


def test_grouping_semantics() -> bool:
    """The grouping contract: shape is invisible, a real regrouping is not."""
    print("\n" + "=" * 80)
    print("GROUPING SEMANTICS TEST (shape ignored, members and order enforced)")
    print("=" * 80)
    passed = True
    with tempfile.TemporaryDirectory(prefix="enforce-use-groups-") as tmp:
        root = Path(tmp)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.0.0"\n', encoding="utf-8")

        # (a) A rustfmt-expanded multi-line block is *already* correct: `--check` must
        # not report it, and default mode must not touch it.
        expanded = _write_fixture(root, "expanded.rs", EXPANDED_FIXTURE)
        before = hashlib.sha256(expanded.read_bytes()).hexdigest()
        code, output = _run_script(root, "--check")
        passed &= _report("(a) fmt-expanded multi-line grouping passes --check",
                          code == 0 and "src/expanded.rs:" not in output,
                          f"exit {code}")
        code, _ = _run_script(root)
        passed &= _report("(a) default mode leaves the expanded file byte-identical",
                          expanded.read_bytes() == EXPANDED_FIXTURE.encode()
                          and hashlib.sha256(expanded.read_bytes()).hexdigest() == before)

        # (a2) In-block item order is rustfmt's: a reversed order with the right members
        # is the same grouping and must pass untouched.
        reversed_ = _write_fixture(root, "reversed.rs", REVERSED_INBLOCK_FIXTURE)
        code, output = _run_script(root, "--check")
        passed &= _report("(a2) reversed in-block order (same members) passes --check",
                          code == 0 and "src/reversed.rs:" not in output, f"exit {code}")
        _run_script(root)
        passed &= _report("(a2) reversed in-block order left untouched",
                          reversed_.read_text(encoding="utf-8") == REVERSED_INBLOCK_FIXTURE)

        # (b1/b2/b3) Real regroupings are reported with a line number.
        for name, text, want_line, label in (
            ("wrong_order.rs", WRONG_GROUP_ORDER_FIXTURE, 3, "(b1) sections out of order"),
            ("unmerged.rs", UNMERGED_CRATE_FIXTURE, 3, "(b2) one crate split over two statements"),
            ("misplaced.rs", MEMBER_IN_WRONG_STATEMENT_FIXTURE, 3,
             "(b3) member in the wrong statement"),
            ("duplicate.rs", DUPLICATE_MEMBER_FIXTURE, 4, "(b4) an extra member"),
        ):
            victim = _write_fixture(root, name, text)
            code, output = _run_script(root, "--check")
            marked = f"src/{name}:{want_line}" in output
            passed &= _report(f"{label} is reported at src/{name}:{want_line}",
                              code == 1 and marked, f"exit {code}")
            # (c) write-back repairs it and the repaired file passes --check
            code, _ = _run_script(root, "--check")
            code_fix, _ = _run_script(root)
            passed &= _report(f"{label} write-back exits 0", code_fix == 0, f"exit {code_fix}")
            code_after, _ = _run_script(root, "--check")
            passed &= _report(f"{label} repaired file passes --check",
                              code_after == 0, f"exit {code_after}")
            victim.unlink()

        # (d) Convergence: write-back output re-checked must be a no-op.
        crash = _write_fixture(root, "converge.rs", WRONG_GROUP_ORDER_FIXTURE)
        _run_script(root)
        repaired = crash.read_text(encoding="utf-8")
        code, _ = _run_script(root, "--check")
        passed &= _report("(d) rewritten output passes --check", code == 0, f"exit {code}")
        code, _ = _run_script(root)
        passed &= _report("(d) second run rewrites nothing",
                          crash.read_text(encoding="utf-8") == repaired)
        crash.unlink()

        # (e) --check never writes.
        victim = _write_fixture(root, "readonly.rs", WRONG_GROUP_ORDER_FIXTURE)
        before = hashlib.sha256(victim.read_bytes()).hexdigest()
        code, _ = _run_script(root, "--check")
        passed &= _report("(e) --check exits 1 on a deviating file", code == 1, f"exit {code}")
        passed &= _report("(e) --check leaves the file byte-identical",
                          hashlib.sha256(victim.read_bytes()).hexdigest() == before)
        victim.unlink()

        # Usage errors stay distinguishable from deviations.
        code, _ = _run_script(root, "--check", "--no-such-flag")
        passed &= _report("(f) unknown flag exits 2", code == 2, f"exit {code}")
        code, _ = _run_script(root, "--check", "--test")
        passed &= _report("(f) --check with --test exits 2", code == 2, f"exit {code}")

    print("\nAll grouping tests PASSED!" if passed else "\nSome grouping tests FAILED!")
    print("=" * 80 + "\n")
    return passed


def test_member_expansion() -> bool:
    """`statement_members` must flatten every shape without losing a member."""
    print("\n" + "=" * 80)
    print("MEMBER EXPANSION TEST")
    print("=" * 80)
    cases = [
        ("std::{collections::HashMap, sync::Arc}",
         ("std::collections::HashMap", "std::sync::Arc")),
        ("std::{sync::Arc, collections::HashMap}",
         ("std::collections::HashMap", "std::sync::Arc")),
        ("a::{b::{c, d}, e}", ("a::b::c", "a::b::d", "a::e")),
        ("a::{self, b}", ("a", "a::b")),
        ("std::{\n"
         "    collections::HashMap,\n"
         "    sync::{atomic::{AtomicU64, Ordering}, Arc},\n"
         "}",
         ("std::collections::HashMap", "std::sync::Arc",
          "std::sync::atomic::AtomicU64", "std::sync::atomic::Ordering")),
        ("std::sync::{Arc, Mutex}", ("std::sync::Arc", "std::sync::Mutex")),
        ("crate::module::Thing", ("crate::module::Thing",)),
        ("::std::sync::Arc", ("std::sync::Arc",)),
    ]
    passed = True
    for text, expected in cases:
        actual = statement_members(text)
        # The fixture text is joined exactly as `extract_use_path` would leave it.
        passed &= _report(" ".join(text.split())[:56],
                          tuple(sorted(expected)) == actual, f"{actual}")
    print("\nAll member-expansion tests PASSED!" if passed
          else "\nSome member-expansion tests FAILED!")
    print("=" * 80 + "\n")
    return passed


def run_selftests() -> bool:
    return (test_underscore_classification()
            and test_member_expansion()
            and test_grouping_semantics())


USAGE = """\
usage: enforce_use_groups.py [--check | --test]

  (no flag)  rewrite the files whose `use` grouping deviates, then run `cargo fmt`
  --check    report `<path>:<first deviating line>` per file whose grouping deviates,
             and write nothing (neither sources nor `cargo fmt`)
  --test     run the built-in classification, member-expansion and grouping self-tests

Exit codes: 0 = clean / written back, 1 = --check found grouping deviations,
            2 = usage error
"""


def parse_args(argv: Sequence[str]) -> Tuple[bool, bool]:
    """Return (check, test). Raises ValueError on unknown or repeated flags."""
    check = False
    test = False
    for arg in argv:
        if arg == "--check":
            if check:
                raise ValueError("--check given more than once")
            check = True
        elif arg == "--test":
            if test:
                raise ValueError("--test given more than once")
            test = True
        else:
            raise ValueError(f"unknown argument: {arg}")
    if check and test:
        raise ValueError("--check and --test are mutually exclusive")
    return check, test


if __name__ == "__main__":
    try:
        print("="*80)
        print("ENFORCE USE STATEMENT GROUPS")
        print("="*80)
        try:
            CHECK, TEST = parse_args(sys.argv[1:])
        except ValueError as exc:
            print(f"error: {exc}\n")
            print(USAGE)
            sys.exit(2)
        print("Loading workspace crates...")
        WORKSPACE_CRATES = load_workspace_crates(Path.cwd())
        if TEST:
            print("Running in test mode...")
            sys.exit(0 if run_selftests() else 1)
        print(f"Found {len(WORKSPACE_CRATES)} workspace crates")
        exit_code = main(check=CHECK)
        print(f"Exiting with code: {exit_code}")
        sys.exit(exit_code)
    except SystemExit:
        raise
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
