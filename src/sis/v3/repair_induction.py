"""Typed symbolic repair induction (v3.4.0, SIS3-401).

Mines ``RepairHypothesisV1`` records from verified before/after source
pairs. Python only: the miner parses both trees, finds the minimal
differing subtree, and anti-unifies operand subtrees into typed
metavariables (``expr:<name>``). Resulting templates are real structured
transformations — pattern match on AST shape, substitute metavariables,
re-emit source via ``ast.unparse``.

Anything the differ cannot type becomes ``generic_strategy`` — a
low-confidence textual class that is never presented as a semantic
transformation. Every typed transformation REQUIRES a semantic contract
digest binding an independently runnable acceptance recipe; the pattern
itself is never evidence of correctness.
"""
from __future__ import annotations

import ast
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    RepairHypothesisV1,
    canonical_digest,
    canonical_json,
)
from .policy import require_permission

_MAX_SOURCE_BYTES = 1 << 20
_MAX_METAVARS = 32


class InductionError(RuntimeError):
    """The evidence cannot support a typed hypothesis."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _template(node: ast.AST, metavars: dict[int, str]) -> dict:
    """Serialize an AST node to a canonical JSON template.

    Subtrees registered in ``metavars`` collapse to ``{"meta": name}``
    holes keyed by ``id(node)``; all other structure is concrete.
    """
    key = id(node)
    if key in metavars:
        return {"meta": metavars[key]}
    if isinstance(node, ast.BinOp):
        return {"node": "BinOp", "op": type(node.op).__name__,
                "left": _template(node.left, metavars),
                "right": _template(node.right, metavars)}
    if isinstance(node, ast.BoolOp):
        return {"node": "BoolOp", "op": type(node.op).__name__,
                "values": [_template(v, metavars) for v in node.values]}
    if isinstance(node, ast.Compare):
        return {"node": "Compare",
                "ops": [type(o).__name__ for o in node.ops],
                "left": _template(node.left, metavars),
                "comparators": [_template(c, metavars)
                                for c in node.comparators]}
    if isinstance(node, ast.Name):
        return {"node": "Name", "id": node.id}
    if isinstance(node, ast.Constant):
        return {"node": "Constant", "value": node.value}
    if isinstance(node, ast.Call):
        return {"node": "Call",
                "func": _template(node.func, metavars),
                "args": [_template(a, metavars) for a in node.args]}
    if isinstance(node, ast.Attribute):
        return {"node": "Attribute",
                "value": _template(node.value, metavars),
                "attr": node.attr}
    raise InductionError(
        "unsupported_syntax",
        f"{type(node).__name__} is outside the supported pattern grammar",
    )


def _first_expr(tree: ast.AST) -> ast.expr | None:
    """The single top-level expression body we transform (return/assign)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            return node.value
        if isinstance(node, ast.Assign) and node.targets:
            return node.value
    return None


def _diff_operators(
    before: ast.AST, after: ast.AST, metavars: dict[int, str]
) -> str:
    """Classify the minimal difference between aligned expression trees.

    Returns a transformation kind and registers operand metavariables.
    """
    if isinstance(before, ast.BinOp) and isinstance(after, ast.BinOp):
        if ast.dump(before.left) == ast.dump(after.left) and \
                ast.dump(before.right) == ast.dump(after.right):
            if type(before.op) is not type(after.op):
                metavars[id(before.left)] = f"expr:lhs"
                metavars[id(after.left)] = f"expr:lhs"
                metavars[id(before.right)] = f"expr:rhs"
                metavars[id(after.right)] = f"expr:rhs"
                return "operator_substitution"
            return "generic_strategy"
        if ast.dump(before.left) == ast.dump(after.right) and \
                ast.dump(before.right) == ast.dump(after.left) and \
                type(before.op) is type(after.op):
            metavars[id(before.left)] = "expr:lhs"
            metavars[id(after.right)] = "expr:lhs"
            metavars[id(before.right)] = "expr:rhs"
            metavars[id(after.left)] = "expr:rhs"
            return "operand_reorder"
        raise InductionError(
            "compounded_difference",
            "operands and operator both changed; no typed hypothesis",
        )
    raise InductionError(
        "unsupported_difference",
        "differing subtrees are not aligned binary operations",
    )


def _match(template: dict, node: ast.AST,
           bindings: dict[str, ast.AST]) -> bool:
    """Structural match of a template against an AST node with binding."""
    if "meta" in template:
        name = template["meta"]
        bound = bindings.get(name)
        if bound is None:
            bindings[name] = node
            return True
        return ast.dump(bound) == ast.dump(node)
    kind = template.get("node")
    if kind == "BinOp" and isinstance(node, ast.BinOp):
        return type(node.op).__name__ == template["op"] and \
            _match(template["left"], node.left, bindings) and \
            _match(template["right"], node.right, bindings)
    if kind == "BoolOp" and isinstance(node, ast.BoolOp):
        return type(node.op).__name__ == template["op"] and \
            len(node.values) == len(template["values"]) and \
            all(_match(t, v, bindings)
                for t, v in zip(template["values"], node.values))
    if kind == "Compare" and isinstance(node, ast.Compare):
        return [type(o).__name__ for o in node.ops] == template["ops"] and \
            _match(template["left"], node.left, bindings) and \
            len(node.comparators) == len(template["comparators"]) and \
            all(_match(t, c, bindings)
                for t, c in zip(template["comparators"], node.comparators))
    if kind == "Name" and isinstance(node, ast.Name):
        return node.id == template["id"]
    if kind == "Constant" and isinstance(node, ast.Constant):
        return node.value == template["value"]
    if kind == "Call" and isinstance(node, ast.Call):
        return _match(template["func"], node.func, bindings) and \
            len(node.args) == len(template["args"]) and \
            all(_match(t, a, bindings)
                for t, a in zip(template["args"], node.args))
    if kind == "Attribute" and isinstance(node, ast.Attribute):
        return node.attr == template["attr"] and \
            _match(template["value"], node.value, bindings)
    return False


def _substitute(template: dict, bindings: dict[str, ast.AST]) -> ast.AST:
    """Instantiate a template into a concrete AST from metavar bindings."""
    if "meta" in template:
        return bindings[template["meta"]]
    kind = template["node"]
    if kind == "BinOp":
        return ast.BinOp(
            left=_substitute(template["left"], bindings),
            op=getattr(ast, template["op"])(),
            right=_substitute(template["right"], bindings))
    if kind == "BoolOp":
        return ast.BoolOp(
            op=getattr(ast, template["op"])(),
            values=[_substitute(t, bindings) for t in template["values"]])
    if kind == "Compare":
        return ast.Compare(
            left=_substitute(template["left"], bindings),
            ops=[getattr(ast, o)() for o in template["ops"]],
            comparators=[_substitute(t, bindings)
                         for t in template["comparators"]])
    if kind == "Name":
        return ast.Name(id=template["id"], ctx=ast.Load())
    if kind == "Constant":
        return ast.Constant(value=template["value"])
    if kind == "Call":
        return ast.Call(
            func=_substitute(template["func"], bindings),
            args=[_substitute(t, bindings) for t in template["args"]],
            keywords=[])
    if kind == "Attribute":
        return ast.Attribute(
            value=_substitute(template["value"], bindings),
            attr=template["attr"], ctx=ast.Load())
    raise InductionError("unsupported_syntax", kind)


def mine_repairs(
    *,
    actor_role: str,
    before_source: str,
    after_source: str,
    receipt: OutcomeReceiptV1,
    failure_signature: str,
    semantic_contract_digest: str | None,
    test_recipe: tuple[str, ...],
    miner_identity: str = "sis-v3-miner",
    repository_identity: str | None = None,
    family_id: str | None = None,
    evidence_refs: tuple[str, ...] = (),
) -> RepairHypothesisV1:
    """Mine a typed hypothesis from one verified before/after pair.

    Only ``pass`` receipts may seed a typed transformation — a failed
    episode proves nothing about the fix. The caller supplies the
    evaluator's suite commitment as ``semantic_contract_digest`` and the
    acceptance recipe; the hypothesis never asserts its own correctness.
    """
    require_permission(actor_role, "candidate:write")
    if not isinstance(receipt, OutcomeReceiptV1):
        raise ContractError("receipt must be an OutcomeReceiptV1")
    for name, src in (("before_source", before_source),
                      ("after_source", after_source)):
        if not isinstance(src, str) or not src.strip() \
                or len(src.encode()) > _MAX_SOURCE_BYTES:
            raise ContractError(f"{name} must be bounded source text")
    if receipt.outcome != "pass":
        raise InductionError(
            "unverified_repair",
            "only independently passing outcomes may seed a transformation",
        )
    try:
        before_tree = ast.parse(before_source)
        after_tree = ast.parse(after_source)
    except SyntaxError as exc:
        raise InductionError("unparseable_source", str(exc)) from exc
    before_expr = _first_expr(before_tree)
    after_expr = _first_expr(after_tree)
    if before_expr is None or after_expr is None:
        raise InductionError("no_transformable_expression")
    metavars: dict[int, str] = {}
    kind = _diff_operators(before_expr, after_expr, metavars)
    distinct = sorted(set(metavars.values()))
    if len(distinct) > _MAX_METAVARS:
        raise InductionError("too_many_metavariables")
    seed = {
        "language": "python",
        "before": ast.dump(before_expr),
        "after": ast.dump(after_expr),
        "receipt_digest": receipt.digest,
    }
    return RepairHypothesisV1(
        schema_version=1,
        hypothesis_id="hyp-" + hashlib.sha256(
            canonical_json(seed)).hexdigest()[:24],
        language="python",
        transformation_kind=kind,
        source_pattern=_template(before_expr, metavars),
        target_pattern=_template(after_expr, metavars),
        metavariables=tuple(distinct),
        failure_signature=failure_signature,
        preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(),
        required_dependencies=(),
        semantic_contract_digest=semantic_contract_digest,
        test_recipe=tuple(test_recipe),
        evidence_refs=tuple(dict.fromkeys(
            evidence_refs + (receipt.digest,))),
        repository_identity=repository_identity,
        family_id=family_id,
        miner_identity=miner_identity,
    )


@dataclass(frozen=True)
class PatternMatch:
    lineno: int
    bindings: Mapping[str, str]  # metavar -> ast.dump of bound subtree


def find_matches(source: str, hypothesis: RepairHypothesisV1) -> tuple[PatternMatch, ...]:
    """Locate every expression in ``source`` matching source_pattern."""
    if hypothesis.language != "python":
        raise InductionError("unsupported_language", hypothesis.language)
    tree = ast.parse(source)
    found: list[PatternMatch] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare,
                                 ast.Call, ast.Attribute)):
            continue
        bindings: dict[str, ast.AST] = {}
        if _match(hypothesis.source_pattern, node, bindings):
            found.append(PatternMatch(
                lineno=node.lineno,
                bindings={k: ast.dump(v) for k, v in bindings.items()}))
    return tuple(sorted(found, key=lambda m: m.lineno))


def apply_hypothesis(source: str, hypothesis: RepairHypothesisV1) -> str | None:
    """Rewrite the FIRST source_pattern match via target_pattern.

    Returns patched source, or None when nothing matches (abstain).
    Operates on whole-line replacements of the matched expression's line
    span so the surrounding program is untouched.
    """
    if hypothesis.language != "python":
        raise InductionError("unsupported_language", hypothesis.language)
    tree = ast.parse(source)
    target_node = None
    bindings: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare,
                                 ast.Call, ast.Attribute)):
            continue
        candidate: dict[str, ast.AST] = {}
        if _match(hypothesis.source_pattern, node, candidate):
            target_node, bindings = node, candidate
            break
    if target_node is None:
        return None
    replacement = _substitute(hypothesis.target_pattern, bindings)
    lines = source.splitlines(keepends=True)
    start = target_node.lineno - 1
    end = getattr(target_node, "end_lineno", target_node.lineno)
    if end == target_node.lineno:
        # Single-line match: splice only the expression's column span so
        # surrounding tokens (e.g. ``return``) are preserved.
        line = lines[start]
        line = (line[:target_node.col_offset]
                + ast.unparse(replacement)
                + line[target_node.end_col_offset:])
        lines[start] = line
        return "".join(lines)
    # Multi-line match: rewrite the whole module around the replaced node.
    _replace_node(tree, target_node, replacement)
    return ast.unparse(tree) + "\n"


def _replace_node(tree: ast.AST, old: ast.AST, new: ast.AST) -> None:
    for parent in ast.walk(tree):
        for field in ast.iter_fields(parent):
            name, value = field
            if value is old:
                setattr(parent, name, new)
                return
            if isinstance(value, list):
                for i, item in enumerate(value):
                    if item is old:
                        value[i] = new
                        return
