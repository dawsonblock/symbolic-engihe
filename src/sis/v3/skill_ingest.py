"""Ingest real agent skills as unqualified SIS candidates (v3.3, M10).

A skill is a directory with ``SKILL.md`` (YAML frontmatter plus a
Markdown body) and optional ``references/``, ``scripts/`` and
``assets/`` files — the format used by the vskill and skills catalogs.
This module turns one into a bounded ``CandidateV1`` of type
``skill_bundle`` and submits it at PROPOSED.

The ingester is a packaging adapter, never a promotion authority:

- parsing is bounded and dependency-free (no YAML library, no code
  execution, no network);
- only regular UTF-8 files inside the skill directory are read; symlinks,
  traversal, hidden files, oversized bodies and oversized resource sets
  are refused;
- resource files are recorded by digest and size, never inlined, because
  the candidate record is capped at 64 KiB;
- scan findings are advisory and reported, never a qualification;
- a status claimed by the source (frontmatter or bundle manifest) is
  ignored — every ingested skill enters at PROPOSED;
- the candidate id is derived from name + content digest, so re-ingesting
  identical content is a no-op and changed content is a new candidate.
"""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .candidates import (CandidateConflict, CandidateRegistry,
                         content_digest)
from .contracts import CandidateV1, ContractError, loads_json
from .skill_package import PackageError, import_bundle

SKILL_FILE = "SKILL.md"
FORMAT = "sis-skill/1"

MAX_FRONTMATTER_BYTES = 8 * 1024
MAX_BODY_BYTES = 24 * 1024
CHUNK_CHARS = 4000
MAX_INSTRUCTION_CHUNKS = 8
MAX_RESOURCES = 64
MAX_RESOURCE_BYTES = 16 * 1024 * 1024
MAX_RESOURCE_PATH = 256
MAX_STEPS = 32
MAX_STEP_CHARS = 320
MAX_FALLBACK_STEPS = 8
MAX_SCAN_SKILLS = 500
MAX_DEPTH = 6

_KEY = re.compile(r"^([A-Za-z0-9_-]{1,64}):[ \t]*(.*)$")
_LIST_ITEM = re.compile(r"^(?:[-*+]|\d{1,3}[.)])[ \t]+(.+)$")
_SLUG = re.compile(r"[^a-z0-9]+")
_EXEC = re.compile(
    r"(\brm\s+-rf\b|\bcurl\s|\bwget\s|\bsudo\s|\bchmod\s"
    r"|\beval\s*[\(\"'$]|\bexec\s*[\(\"'$]|\bbase64\s+-d"
    r"|\bpowershell\b|\bsh\s+-c\b|>\s*/)", re.I)
_INJECTION = re.compile(
    r"(ignore (all )?(previous|prior|above) instructions"
    r"|disregard (the )?(system|previous) (prompt|instructions)"
    r"|you are now\b|act as (the )?system"
    r"|reveal (the )?(system prompt|api key|secret)"
    r"|exfiltrat\w*|do not (tell|inform) the user"
    r"|<\|?(system|im_start)\|?>)", re.I)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class SkillIngestError(RuntimeError):
    """A skill cannot be read, parsed, or registered as a candidate."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _mtime(path: Path) -> str:
    return datetime.fromtimestamp(
        path.stat().st_mtime, timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")


def _check_text(text: str, name: str) -> str:
    if _CONTROL.search(text):
        raise SkillIngestError(f"{name}_control_characters")
    return text


def _parse_frontmatter(header: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    index = 0
    while index < len(header):
        line = header[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace() or line.lstrip().startswith("-"):
            # Nested YAML is not interpreted; the body carries the content.
            continue
        match = _KEY.match(line)
        if match is None:
            raise SkillIngestError("skill_frontmatter_malformed")
        key, value = match.group(1), match.group(2).strip()
        if value in (">", "|", ">-", "|-", ">+", "|+"):
            # Folded/literal block scalar: take the indented continuation.
            block: list[str] = []
            while index < len(header) and (
                    header[index][:1].isspace() or not header[index].strip()):
                block.append(header[index].strip())
                index += 1
            joiner = "\n" if value.startswith("|") else " "
            value = joiner.join(part for part in block if part)
        elif len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key in fields:
            raise SkillIngestError("skill_frontmatter_duplicate_key")
        if len(value) > 1024:
            raise SkillIngestError("skill_frontmatter_too_large")
        fields[key] = _check_text(value, "skill_frontmatter")
        if len(fields) > 32:
            raise SkillIngestError("skill_frontmatter_too_large")
    return fields


def read_skill_name(path: str | Path) -> str | None:
    """Read only the frontmatter name; never hashes resources."""
    skill_file = Path(path) / SKILL_FILE
    if skill_file.is_symlink() or not skill_file.is_file():
        return None
    try:
        frontmatter, _ = _split_skill_text(skill_file.read_bytes())
    except (OSError, SkillIngestError):
        return None
    return frontmatter.get("name") or None



def _split_skill_text(raw: bytes) -> tuple[dict[str, str], str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SkillIngestError("skill_not_utf8") from exc
    if len(raw) > MAX_FRONTMATTER_BYTES + MAX_BODY_BYTES:
        raise SkillIngestError("skill_body_too_large")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            header = "\n".join(lines[1:index]).encode("utf-8")
            if len(header) > MAX_FRONTMATTER_BYTES:
                raise SkillIngestError("skill_frontmatter_too_large")
            return _parse_frontmatter(lines[1:index]), "\n".join(
                lines[index + 1:])
    raise SkillIngestError("skill_frontmatter_unterminated")


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[*_`]", "", text)).strip()


def _chunks(body: str) -> tuple[str, ...]:
    """Split the body into contract-bounded chunks without losing text.

    The v1 contract caps any single JSON string at 4 KiB, while real
    ``SKILL.md`` bodies are longer. Paragraph-aligned chunks keep the
    whole body, deterministically, under that per-string bound.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        while len(paragraph) > CHUNK_CHARS:
            cut = paragraph.rfind(" ", 0, CHUNK_CHARS)
            if cut < CHUNK_CHARS // 2:
                cut = CHUNK_CHARS
            piece, paragraph = paragraph[:cut].rstrip(), \
                paragraph[cut:].lstrip()
            if current:
                chunks.append(current)
                current = ""
            chunks.append(piece)
        if not paragraph:
            continue
        if not current:
            current = paragraph
        elif len(current) + 2 + len(paragraph) <= CHUNK_CHARS:
            current = current + "\n\n" + paragraph
        else:
            chunks.append(current)
            current = paragraph
    if current:
        chunks.append(current)
    if len(chunks) > MAX_INSTRUCTION_CHUNKS:
        raise SkillIngestError("skill_body_too_large")
    return tuple(chunks)


def _steps(body: str) -> tuple[str, ...]:
    """Extract bounded advisory steps; a heuristic, not a semantic parse."""
    steps: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "```")):
            continue
        match = _LIST_ITEM.match(stripped)
        if match is None:
            continue
        text = _clean(match.group(1))
        if 3 <= len(text) <= MAX_STEP_CHARS:
            steps.append(text)
        if len(steps) >= MAX_STEPS:
            break
    if steps:
        return tuple(steps)
    for line in body.splitlines():
        text = _clean(line)
        if 12 <= len(text) <= MAX_STEP_CHARS and not line.strip().startswith(
                ("#", "```", "|")):
            steps.append(text)
        if len(steps) >= MAX_FALLBACK_STEPS:
            break
    return tuple(steps)


def scan_findings(candidate: CandidateV1) -> list[str]:
    """Advisory findings: shell tokens in served steps, injection in prose.

    Nothing here is a qualification signal. Shell tokens in *steps* matter
    because steps are the text the gateway delivers; scanning whole bodies
    for them would flag every code sample, so the body is checked for
    prompt-injection phrasing instead.
    """
    texts = [text for text in candidate.payload.get("instructions", ())
             if isinstance(text, str)]
    texts += [text for text in candidate.payload.get("steps", ())
              if isinstance(text, str)]
    findings: set[str] = set()
    for text in texts:
        for match in _EXEC.finditer(text):
            findings.add("shell_execution_token:"
                         + match.group(0).strip().lower()[:32])
        for match in _INJECTION.finditer(text):
            findings.add("prompt_injection_phrase:"
                         + match.group(0).lower()[:64])
    return sorted(findings)


def _resources(root: Path) -> list[dict]:
    """Hash resource files under ``root``; contents are never inlined."""
    out: list[dict] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in dirnames:
            if (base / name).is_symlink():
                raise SkillIngestError("skill_symlink_refused:" + name)
        dirnames[:] = sorted(
            name for name in dirnames if not name.startswith("."))
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            relative = path.relative_to(root).as_posix()
            if relative == SKILL_FILE or filename.startswith("."):
                continue
            if path.is_symlink() or not path.is_file():
                raise SkillIngestError("skill_symlink_refused:" + relative)
            if len(relative) > MAX_RESOURCE_PATH:
                raise SkillIngestError("skill_resource_path_too_long")
            size = path.stat().st_size
            total += size
            if total > MAX_RESOURCE_BYTES:
                raise SkillIngestError("skill_resources_too_large")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            out.append({"path": relative, "sha256": digest, "bytes": size})
            if len(out) > MAX_RESOURCES:
                raise SkillIngestError("skill_too_many_resources")
    return out


def load_skill(path: str | Path) -> dict:
    """Parse one skill directory into a bounded, normalized source."""
    root = Path(path)
    if root.is_symlink():
        raise SkillIngestError("skill_symlink_refused")
    if not root.is_dir():
        raise SkillIngestError("skill_directory_missing")
    skill_file = root / SKILL_FILE
    if skill_file.is_symlink() or not skill_file.is_file():
        raise SkillIngestError("skill_file_missing")
    try:
        raw = skill_file.read_bytes()
    except OSError as exc:
        raise SkillIngestError("skill_file_unreadable") from exc
    frontmatter, body = _split_skill_text(raw)
    body = _check_text(body, "skill_body").strip()
    if not body:
        raise SkillIngestError("skill_body_missing")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise SkillIngestError("skill_body_too_large")
    name = frontmatter.get("name", "").strip()
    description = frontmatter.get("description", "").strip()
    if not name:
        raise SkillIngestError("skill_name_missing")
    if not description:
        raise SkillIngestError("skill_description_missing")
    if len(name) > 128 or len(description) > 1024:
        raise SkillIngestError("skill_frontmatter_too_large")
    extras = {
        key: value for key, value in sorted(frontmatter.items())
        if key not in {"name", "description", "version"}
    }
    version = frontmatter.get("version", "").strip()
    if len(version) > 128 or len(extras) > 16 or \
            sum(len(key) + len(value) for key, value in extras.items()) > 4096:
        raise SkillIngestError("skill_frontmatter_too_large")
    return {
        "kind": "skill_dir",
        "name": name,
        "description": description,
        "version": version,
        "instructions": _chunks(body),
        "steps": _steps(body),
        "resources": _resources(root),
        "frontmatter": extras,
        "created_at": _mtime(skill_file),
    }


def _slug(name: str) -> str:
    slug = _SLUG.sub("-", name.lower()).strip("-")[:32].strip("-")
    return slug or "skill"


def skill_candidate(
    source: dict,
    *,
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    generator_identity: str = "sis-skill-ingest",
    created_at: str | None = None,
    source_name: str | None = None,
    applicability=(),
    counterexamples=(),
) -> CandidateV1:
    """Build the PROPOSED candidate for a parsed skill source."""
    payload = {
        "format": FORMAT,
        "name": source["name"],
        "description": source["description"],
        "version": source["version"],
        "instructions": list(source["instructions"]),
        "steps": list(source["steps"]),
        "resources": list(source["resources"]),
        "frontmatter": dict(source["frontmatter"]),
        "source": {
            "kind": source["kind"],
            "name": source_name or source["name"],
        },
    }
    try:
        digest = content_digest("skill_bundle", payload)
        return CandidateV1(
            schema_version=1,
            candidate_id=f"skill-{_slug(source['name'])}-{digest[:12]}",
            candidate_type="skill_bundle",
            content_digest=digest,
            parent_candidate_ids=(),
            source_episode_ids=(),
            generator_identity=generator_identity,
            target_agent=target_agent,
            target_task_family=target_task_family,
            repository_scope={"kind": scope_kind, "value": scope_value},
            applicability_predicate=tuple(applicability),
            known_counterexamples=tuple(counterexamples),
            payload=payload,
            created_at=created_at or source["created_at"],
        )
    except ContractError as exc:
        raise SkillIngestError(f"skill_candidate_invalid:{exc}") from exc


def ingest_skill(
    path: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str = "learner",
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    created_at: str | None = None,
    source_name: str | None = None,
) -> dict:
    """Parse, scan and register one skill at PROPOSED (idempotent)."""
    source = load_skill(path)
    candidate = skill_candidate(
        source, scope_kind=scope_kind, scope_value=scope_value,
        target_agent=target_agent, target_task_family=target_task_family,
        created_at=created_at, source_name=source_name)
    findings = scan_findings(candidate)
    existing = registry.lookup(candidate.candidate_id)
    if existing is not None:
        record, state = existing
        if record.content_digest != candidate.content_digest:
            raise SkillIngestError("candidate_id_collision")
        return {
            "status": "already_present",
            "candidate_id": record.candidate_id,
            "digest": record.digest,
            "state": state,
            "name": source["name"],
            "steps": len(source["steps"]),
            "resources": len(source["resources"]),
            "scan_findings": findings,
        }
    try:
        registry.submit(candidate, actor_role=actor_role)
    except ContractError as exc:
        raise SkillIngestError(f"skill_candidate_invalid:{exc}") from exc
    return {
        "status": "submitted",
        "candidate_id": candidate.candidate_id,
        "digest": candidate.digest,
        "state": "proposed",
        "name": source["name"],
        "steps": len(source["steps"]),
        "resources": len(source["resources"]),
        "scan_findings": findings,
    }


def discover_skills(root: str | Path) -> list[Path]:
    """Find skill directories under ``root`` (bounded, no symlink walk)."""
    root = Path(root)
    if root.is_symlink():
        raise SkillIngestError("skill_symlink_refused")
    if not root.is_dir():
        raise SkillIngestError("skill_directory_missing")
    if (root / SKILL_FILE).is_file():
        return [root]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        depth = len(base.relative_to(root).parts)
        dirnames[:] = sorted(
            name for name in dirnames
            if not name.startswith(".") and
            not (base / name).is_symlink())
        if depth > MAX_DEPTH:
            dirnames[:] = []
            continue
        if SKILL_FILE in filenames:
            found.append(base)
            if len(found) >= MAX_SCAN_SKILLS:
                break
    return sorted(found)


def ingest_tree(
    root: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str = "learner",
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    created_at: str | None = None,
) -> list[dict]:
    """Ingest every skill under ``root``; failures are recorded per skill."""
    root = Path(root)
    report: list[dict] = []
    for skill_dir in discover_skills(root):
        relative = skill_dir.relative_to(root).as_posix() \
            if skill_dir != root else skill_dir.name
        try:
            entry = ingest_skill(
                skill_dir, registry, actor_role=actor_role,
                scope_kind=scope_kind, scope_value=scope_value,
                target_agent=target_agent,
                target_task_family=target_task_family,
                created_at=created_at, source_name=relative)
        except (SkillIngestError, PackageError, CandidateConflict) as exc:
            report.append({"path": relative, "status": "rejected",
                           "error": str(exc)})
            continue
        report.append({"path": relative, **entry})
    return report


def ingest_path(
    path: str | Path,
    registry: CandidateRegistry,
    *,
    actor_role: str = "learner",
    scope_kind: str,
    scope_value: str,
    target_agent: str = "agent",
    target_task_family: str = "general",
    created_at: str | None = None,
) -> list[dict]:
    """Ingest a skill directory, a skill tree, or a vskill-style bundle."""
    path = Path(path)
    if (path / "manifest.json").is_file() and \
            (path / "payload.json").is_file():
        try:
            candidate = CandidateV1.from_dict(
                loads_json((path / "payload.json").read_bytes()))
            digest = import_bundle(path, registry, actor_role=actor_role)
        except (PackageError, ContractError, OSError) as exc:
            return [{"path": path.name, "status": "rejected",
                     "error": str(exc)}]
        return [{"path": path.name, "status": "submitted",
                 "candidate_id": candidate.candidate_id,
                 "digest": digest, "state": "proposed",
                 "name": candidate.candidate_id,
                 "steps": len(candidate.payload.get("steps", ())),
                 "resources": 0,
                 "scan_findings": scan_findings(candidate)}]
    return ingest_tree(
        path, registry, actor_role=actor_role, scope_kind=scope_kind,
        scope_value=scope_value, target_agent=target_agent,
        target_task_family=target_task_family, created_at=created_at)
