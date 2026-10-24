"""Semantic gates for patch-transforming procedures (SIS3-141, v3.2.1).

The audited failure: an operator-swap recipe learned from local examples
rewrote ``remaining_balance``'s ``a - b`` into ``a + b`` — lexically plausible,
semantically wrong. The v3.1.x heuristic then generalized it further:
``a + b`` -> ``a * b`` and ``x - y`` -> ``x + y`` slipped through as
"same-class" swaps, and operand reordering (``a - b`` -> ``b - a``) was not
detected at all.

These checks are a *filter*, never a proof: EVERY operator substitution and
every operand reorder is flagged — algebraic classes (commutative etc.)
do not establish semantic equivalence, and side-effect order, float/NaN
behavior, and Boolean short-circuiting all live outside them. A
patch-transforming procedure is safe only when an independently runnable
semantic/property/regression contract passes — that is why
``requires_semantic_contract`` stays the load-bearing gate.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum


class OpClass(Enum):
    COMMUTATIVE = "commutative"      # +, *, ==, !=, and, or
    NONCOMMUTATIVE = "noncommutative"  # -, /, //, %, **, <, >, <=, >=
    OTHER = "other"


_COMMUTATIVE = (ast.Add, ast.Mult, ast.Eq, ast.NotEq, ast.And, ast.Or)
_NONCOMMUTATIVE = (
    ast.Sub, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE,
)


def op_class(node: ast.AST) -> OpClass:
    """Classify an operator node by the metamorphic relations it satisfies."""
    if isinstance(node, _COMMUTATIVE):
        return OpClass.COMMUTATIVE
    if isinstance(node, _NONCOMMUTATIVE):
        return OpClass.NONCOMMUTATIVE
    return OpClass.OTHER


@dataclass(frozen=True)
class OperatorChange:
    lineno: int
    old_class: OpClass
    new_class: OpClass
    kind: str = "operator_swap"  # operator_swap | operand_reorder | structural


def operator_changes(source: str, patched: str) -> list[OperatorChange]:
    """Diff two Python sources at operator granularity (AST, not text)."""
    try:
        old_tree = ast.parse(source)
        new_tree = ast.parse(patched)
    except SyntaxError as exc:
        raise ValueError("unparseable source") from exc
    old_ops = _collect(old_tree)
    new_ops = _collect(new_tree)
    changes: list[OperatorChange] = []
    if len(old_ops) != len(new_ops):
        # Structural change beyond a pure operator swap; report at top level.
        changes.append(OperatorChange(0, OpClass.OTHER, OpClass.OTHER,
                                      kind="structural"))
        return changes
    for (old_node, old_lineno), (new_node, new_lineno) in zip(old_ops, new_ops):
        old_cls = _node_op_class(old_node)
        new_cls = _node_op_class(new_node)
        old_operator = _operator_node(old_node)
        new_operator = _operator_node(new_node)
        if type(old_node) is not type(new_node) or old_cls != new_cls \
                or type(old_operator) is not type(new_operator):
            changes.append(OperatorChange(old_lineno, old_cls, new_cls))
        elif _operands_reordered(old_node, new_node):
            changes.append(OperatorChange(
                old_lineno, old_cls, new_cls, kind="operand_reorder"))
    return changes


def _node_op_class(node: ast.AST) -> OpClass:
    """Class of the operator inside a BinOp/BoolOp/Compare expression."""
    if isinstance(node, (ast.BinOp, ast.BoolOp)):
        return op_class(node.op)
    if isinstance(node, ast.Compare):
        classes = {op_class(op) for op in node.ops}
        return classes.pop() if len(classes) == 1 else OpClass.OTHER
    return OpClass.OTHER


def _operator_node(node: ast.AST):
    """The operator node inside a BinOp/BoolOp/Compare expression."""
    if isinstance(node, (ast.BinOp, ast.BoolOp)):
        return node.op
    if isinstance(node, ast.Compare):
        return node.ops[0] if node.ops else None
    return None


def metamorphic_violations(changes: list[OperatorChange]) -> list[str]:
    """Flag every operator substitution or operand reorder.

    Operator classes are algebraic hints, not semantics: ``+`` -> ``*``
    stays commutative yet changes meaning. Nothing here is
    "presumptively safe" — a flagged change must be discharged by an
    independently executed semantic contract, not waived by class.
    """
    problems: list[str] = []
    for change in changes:
        if change.kind == "structural":
            problems.append("structural change beyond an operator swap")
        elif change.kind == "operand_reorder":
            problems.append(
                f"line {change.lineno}: operand reorder under a "
                f"{change.old_class.value} operator may alter semantics"
            )
        elif change.old_class == change.new_class:
            problems.append(
                f"line {change.lineno}: same-class operator substitution "
                f"({change.old_class.value}) is not semantics-preserving "
                "by class alone"
            )
        else:
            problems.append(
                f"line {change.lineno}: {change.old_class.value} -> "
                f"{change.new_class.value} operator swap alters symmetry"
            )
    return problems


def _operands_reordered(old_node: ast.AST, new_node: ast.AST) -> bool:
    """Same operator type but its operands changed shape/order."""
    if isinstance(old_node, ast.BinOp) and isinstance(new_node, ast.BinOp):
        return ast.dump(old_node.left) != ast.dump(new_node.left) or \
            ast.dump(old_node.right) != ast.dump(new_node.right)
    if isinstance(old_node, ast.BoolOp) and isinstance(new_node, ast.BoolOp):
        return [ast.dump(v) for v in old_node.values] != \
            [ast.dump(v) for v in new_node.values]
    if isinstance(old_node, ast.Compare) and isinstance(new_node, ast.Compare):
        return ast.dump(old_node.left) != ast.dump(new_node.left) or \
            [ast.dump(c) for c in old_node.comparators] != \
            [ast.dump(c) for c in new_node.comparators]
    return False


def _collect(tree: ast.AST) -> list[tuple[ast.AST, int]]:
    ops: list[tuple[ast.AST, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp):
            ops.append((node, node.lineno))
        elif isinstance(node, ast.BoolOp):
            ops.append((node, node.lineno))
        elif isinstance(node, ast.Compare):
            ops.append((node, node.lineno))
    return ops


def requires_semantic_contract(has_patch_effect: bool, semantic_contract_digest) -> bool:
    """Patch-transforming guidance requires verified task intent."""
    return not has_patch_effect or semantic_contract_digest is not None
