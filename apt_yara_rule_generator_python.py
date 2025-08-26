#!/usr/bin/env python3
"""
APT YARA Rule Generator
=======================

Generates YARA rules for APT/malware families from simple JSON, YAML, or CSV
indicator files. Designed to be explicit, readable, and easy to audit.

Key features
------------
- Input formats: JSON (native), YAML (if PyYAML installed), CSV (simple schema)
- Supports strings (text/regex/hex), SHA256 hashes, PE imphash, PE imports,
  section names & entropy checks, mutex/registry/domains/URLs as strings
- Sensible gating for PE files (MZ header) when filetype == "pe"
- Configurable threshold: require N of strings to match ("N of ($s*)")
- Clean rule naming: safe identifiers, family & tags, meta with references
- One .yar file with one rule per family entry in your input

Quick start
-----------
1) Create a JSON like the example below (or run with --example to output one):

{
  "families": [
    {
      "name": "APT28",
      "filetype": "pe",
      "tags": ["apt", "windows", "pe"],
      "references": [
        "https://example.org/apt28-report",
        "https://example.org/blog-post"
      ],
      "iocs": {
        "sha256": [
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ],
        "imphash": [
          "1a79a4d60de6718e8e5b326e338ae533"
        ],
        "imports": [
          {"func":"HttpOpenRequestA"},
          {"dll":"WININET.dll", "func":"InternetOpenA"}
        ],
        "sections": [
          {"name": ".text", "min_entropy": 6.0},
          {"name": ".rdata"}
        ],
        "strings": [
          "Global\\APT28Mutex",
          {"value":"HKCU\\Software\\BadKey", "nocase": true, "wide": true, "fullword": true},
          {"regex":"https?:\\/\\/[a-z0-9_.-]+\\/[a-z0-9_\/-]+", "nocase": true},
          {"hex":"90 90 E8 ?? ?? ?? 68"}
        ],
        "domains": ["c2.example.com"],
        "urls":    ["http://c2.example.com/update"],
        "mutex":   ["Global\\APT28Mutex"],
        "registry":["HKCU\\Software\\BadKey"]
      }
    }
  ]
}

2) Run:
   python apt_yara_gen.py --in apt_iocs.json --out APT.yar --author "Your Name" \
                          --min-strings 2 --rule-prefix APT --version 1.0

CSV schema (simple)
-------------------
Columns: family,type,value,dll,flags,tag,ref,filetype
Examples rows:
  APT28,string,Global\\APT28Mutex,,,apt,https://ref,pe
  APT28,regex,https?:\\/\\/[a-z0-9_.-]+\\/[a-z0-9_\/-]+,,,apt,https://ref,pe
  APT28,hex,90 90 E8 ?? ?? ?? 68,,,apt,https://ref,pe
  APT28,sha256,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,,,,,pe
  APT28,imphash,1a79a4d60de6718e8e5b326e338ae533,,,,,pe
  APT28,import,HttpOpenRequestA,WININET.dll,,,,pe
  APT28,section,.text,,entropy>6.0,,,pe

Notes
-----
- Requires YARA 4.x for modules used (pe, hash). Condition snippets are
  conservative and avoid exotic features for portability.
- SHA256 hash comparisons use: hash.sha256(0, filesize) == "<hex>"
- imphash comparisons use: pe.imphash() == "<hex>"
- Import checks use regex fallbacks when DLL is unknown: pe.imports(/.*/, /Func/i)
- String modifiers supported: ascii, wide, nocase, fullword (as applicable)

"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional YAML support
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


# ---------------------------- Utilities ------------------------------------

def today_iso() -> str:
    return dt.date.today().isoformat()


def slugify_identifier(s: str) -> str:
    """Make a safe YARA rule identifier: [A-Za-z_][A-Za-z0-9_]*"""
    s = re.sub(r"[^A-Za-z0-9_]+", "_", s)
    if not re.match(r"^[A-Za-z_]", s):
        s = f"_{s}"
    return s


def dedup(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


# ----------------------------- Models --------------------------------------

@dataclass
class ImportSpec:
    dll: Optional[str] = None
    func: Optional[str] = None

    @staticmethod
    def from_any(x: Any) -> "ImportSpec":
        if isinstance(x, dict):
            return ImportSpec(dll=x.get("dll"), func=x.get("func"))
        elif isinstance(x, str):
            # Just a function name
            return ImportSpec(func=x)
        else:
            raise ValueError(f"Invalid import spec: {x!r}")


@dataclass
class SectionSpec:
    name: str
    min_entropy: Optional[float] = None

    @staticmethod
    def from_any(x: Any) -> "SectionSpec":
        if isinstance(x, dict):
            name = x.get("name")
            if not name:
                raise ValueError("section requires 'name'")
            return SectionSpec(name=name, min_entropy=x.get("min_entropy"))
        elif isinstance(x, str):
            # allow e.g. ".text" or ".text:entropy>6.0"
            m = re.match(r"^([^:]+)(?::entropy>([0-9.]+))?$", x)
            if m:
                nm, ent = m.group(1), m.group(2)
                return SectionSpec(name=nm, min_entropy=float(ent) if ent else None)
            return SectionSpec(name=x)
        else:
            raise ValueError(f"Invalid section spec: {x!r}")


@dataclass
class StringSpec:
    kind: str  # 'text' | 'regex' | 'hex'
    value: str
    ascii: bool = True
    wide: bool = True
    nocase: bool = False
    fullword: bool = False

    @staticmethod
    def from_any(x: Any) -> "StringSpec":
        if isinstance(x, dict):
            if "hex" in x:
                return StringSpec("hex", x["hex"], False, False, False, False)
            if "regex" in x:
                return StringSpec("regex", x["regex"], False, False, bool(x.get("nocase", False)), False)
            # default text string
            return StringSpec(
                "text",
                x.get("value", ""),
                bool(x.get("ascii", True)),
                bool(x.get("wide", True)),
                bool(x.get("nocase", False)),
                bool(x.get("fullword", False)),
            )
        elif isinstance(x, str):
            # heuristics: /regex/i or {..hex..}
            if x.startswith("/") and x.rstrip().endswith("/"):
                return StringSpec("regex", x[1:-1], False, False, False, False)
            if x.startswith("/" ) and x.rstrip().endswith("/i"):
                return StringSpec("regex", x[1:-2], False, False, True, False)
            if x.strip().startswith("{") and x.strip().endswith("}"):
                # raw hex pattern provided
                return StringSpec("hex", x.strip()[1:-1].strip(), False, False, False, False)
            return StringSpec("text", x)
        else:
            raise ValueError(f"Invalid string spec: {x!r}")

    def to_yara(self, ident: str) -> str:
        if self.kind == "hex":
            pattern = self.value
            return f"  {ident} = {{{pattern}}}"
        if self.kind == "regex":
            flags = "i" if self.nocase else ""
            return f"  {ident} = /{self.value}/{flags}"
        # text
        # Escape quotes and backslashes for YARA string literal
        val = self.value.replace("\\", r"\\").replace('"', r'\"')
        mods = []
        if self.ascii:
            mods.append("ascii")
        if self.wide:
            mods.append("wide")
        if self.nocase:
            mods.append("nocase")
        if self.fullword:
            mods.append("fullword")
        mods_s = (" " + " ".join(mods)) if mods else ""
        return f"  {ident} = \"{val}\"{mods_s}"


@dataclass
class Family:
    name: str
    filetype: str = "pe"  # pe|elf|macho|any
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    iocs: Dict[str, Any] = field(default_factory=dict)


# -------------------------- Parsing Inputs ---------------------------------

def load_input(path: Path) -> List[Family]:
    ext = path.suffix.lower()
    if ext in {".json"}:
        data = json.loads(path.read_text(encoding="utf-8"))
        return parse_object(data)
    elif ext in {".yml", ".yaml"}:
        if yaml is None:
            raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return parse_object(data)
    elif ext == ".csv":
        return parse_csv(path)
    else:
        raise ValueError(f"Unsupported input format: {ext}")


def parse_object(obj: Dict[str, Any]) -> List[Family]:
    fams = []
    families = obj.get("families", []) if isinstance(obj, dict) else []
    for f in families:
        fams.append(
            Family(
                name=f.get("name", "Unnamed"),
                filetype=f.get("filetype", "pe"),
                tags=list(f.get("tags", [])),
                references=list(f.get("references", [])),
                iocs=dict(f.get("iocs", {})),
            )
        )
    return fams


def parse_csv(path: Path) -> List[Family]:
    by_family: Dict[str, Family] = {}
    refs_by_family: Dict[str, List[str]] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            fam = (row.get("family") or "Unnamed").strip()
            f = by_family.setdefault(fam, Family(name=fam))
            f.filetype = (row.get("filetype") or f.filetype or "pe").strip() or "pe"

            # references and tags (col optional)
            ref = (row.get("ref") or "").strip()
            if ref:
                refs_by_family.setdefault(fam, []).append(ref)

            tag = (row.get("tag") or "").strip()
            if tag:
                if tag not in f.tags:
                    f.tags.append(tag)

            typ = (row.get("type") or "").strip().lower()
            val = (row.get("value") or "").strip()
            if not typ or not val:
                continue

            if typ in {"sha256", "imphash", "domains", "urls", "mutex", "registry"}:
                f.iocs.setdefault(typ, []).append(val)
            elif typ == "import":
                imp = ImportSpec(dll=(row.get("dll") or None), func=val)
                f.iocs.setdefault("imports", []).append({"dll": imp.dll, "func": imp.func})
            elif typ == "section":
                # flags may contain entropy>6.0
                flags = (row.get("flags") or "").strip()
                min_ent = None
                m = re.search(r"entropy>([0-9.]+)", flags)
                if m:
                    min_ent = float(m.group(1))
                f.iocs.setdefault("sections", []).append({"name": val, "min_entropy": min_ent})
            elif typ in {"string", "regex", "hex"}:
                if typ == "regex":
                    spec = {"regex": val}
                elif typ == "hex":
                    spec = {"hex": val}
                else:
                    spec = {"value": val}
                flags = (row.get("flags") or "").strip().lower()
                if "nocase" in flags:
                    spec["nocase"] = True
                if "wide" in flags:
                    spec["wide"] = True
                if "ascii" in flags:
                    spec["ascii"] = True
                if "fullword" in flags:
                    spec["fullword"] = True
                f.iocs.setdefault("strings", []).append(spec)
            else:
                # ignore unknown types
                pass

    # Attach refs
    for fam, refs in refs_by_family.items():
        by_family[fam].references.extend(dedup(refs))

    return list(by_family.values())


# ---------------------------- YARA Builder ---------------------------------

class YaraBuilder:
    def __init__(self, *, author: str, version: str, rule_prefix: str, min_strings: int = 2, license_text: Optional[str] = None):
        self.author = author
        self.version = version
        self.rule_prefix = rule_prefix
        self.min_strings = max(1, int(min_strings))
        self.license_text = license_text

    def build_ruleset(self, families: List[Family]) -> str:
        pieces = []
        # Header
        hdr = ["// Auto-generated by apt_yara_gen.py", f"// Date: {today_iso()}"]
        if self.license_text:
            hdr.append("// License: " + self.license_text)
        pieces.append("\n".join(hdr))

        need_pe = any((f.filetype.lower() == "pe") for f in families)
        if need_pe:
            pieces.append('import "pe"')
        pieces.append('import "hash"')
        pieces.append("")

        for fam in families:
            pieces.append(self._build_rule_for_family(fam))
            pieces.append("")
        return "\n".join(pieces).rstrip() + "\n"

    def _build_rule_for_family(self, fam: Family) -> str:
        rule_name = slugify_identifier(f"{self.rule_prefix}_{fam.name}_v{self.version.replace('.', '_')}")
        tags = dedup([slugify_identifier(t) for t in (fam.tags or [])] + ["apt"])  # ensure 'apt' tag

        iocs = fam.iocs or {}
        strings: List[StringSpec] = []

        # Strings from dedicated list
        for s in iocs.get("strings", []) or []:
            strings.append(StringSpec.from_any(s))

        # Domains/URLs/Mutex/Registry as strings (if not already provided)
        for k in ["domains", "urls", "mutex", "registry"]:
            for v in iocs.get(k, []) or []:
                strings.append(StringSpec.from_any(str(v)))

        # De-duplicate by (kind, value, flags)
        uniq = []
        seen = set()
        for s in strings:
            key = (s.kind, s.value, s.ascii, s.wide, s.nocase, s.fullword)
            if key not in seen:
                uniq.append(s)
                seen.add(key)
        strings = uniq

        # Build 'strings' section
        str_lines = []
        for idx, s in enumerate(strings, 1):
            ident = f"$s{idx}"
            str_lines.append(s.to_yara(ident))

        # Build condition pieces
        conds = []

        # Filetype gates
        ft = (fam.filetype or "pe").lower()
        if ft == "pe":
            conds.append("uint16(0) == 0x5A4D")  # 'MZ'
        elif ft == "elf":
            conds.append("uint32(0) == 0x7F454C46")  # '\x7FELF'
        elif ft == "macho":
            conds.append("uint32(0) in (0xFEEDFACE,0xFEEDFACF,0xCEFAEDFE,0xCFFAEDFE)")
        else:
            # no gate for 'any'
            pass

        # N of strings
        if strings:
            conds.append(f"{self.min_strings} of ($s*)")

        # imphash
        imphashes = [h.strip().lower() for h in (iocs.get("imphash") or []) if h]
        if imphashes:
            sub = " or ".join([f"pe.imphash() == \"{h}\"" for h in imphashes])
            conds.append(f"( {sub} )")

        # SHA256
        sha256s = [h.strip().lower() for h in (iocs.get("sha256") or []) if h]
        if sha256s:
            sub = " or ".join([f"hash.sha256(0, filesize) == \"{h}\"" for h in sha256s])
            conds.append(f"( {sub} )")

        # Imports
        imports = [ImportSpec.from_any(x) for x in (iocs.get("imports") or [])]
        import_conds = []
        for imp in imports:
            if imp.dll and imp.func:
                dll = re.escape(imp.dll)
                fn = re.escape(imp.func)
                import_conds.append(f"pe.imports(/^{dll}$/i, /^{fn}$/i)")
            elif imp.func:
                fn = re.escape(imp.func)
                import_conds.append(f"pe.imports(/.*/, /^{fn}$/i)")
        if import_conds:
            conds.append("( " + " or ".join(import_conds) + " )")

        # Sections
        sections = [SectionSpec.from_any(x) for x in (iocs.get("sections") or [])]
        sect_conds = []
        for sec in sections:
            nm = sec.name.replace('\\', r'\\').replace('"', r'\\"')
            base = f"pe.section_index(\"{nm}\") >= 0"
            if sec.min_entropy is not None:
                base = (
                    f"( pe.section_index(\"{nm}\") >= 0 and pe.sections[pe.section_index(\"{nm}\")].entropy > {sec.min_entropy:.2f} )"
                )
            sect_conds.append(base)
        if sect_conds:
            conds.append("( " + " or ".join(sect_conds) + " )")

        # Join condition (AND gate for filetype + OR across evidence sets)
        gates = []
        evid = []
        # split gates and evidences
        for c in conds:
            if c.startswith("uint"):
                gates.append(c)
            else:
                evid.append(c)
        condition = " and ".join(gates + (["( " + " or ".join(evid) + " )"] if evid else [])) if (gates or evid) else "true"

        # Meta section
        meta_lines = [
            f'    author = "{self.author}"',
            f'    date = "{today_iso()}"',
            f'    family = "{fam.name}"',
            f'    version = "{self.version}"',
            '    generated_by = "apt_yara_gen.py"',
        ]
        for i, r in enumerate(dedup(fam.references), 1):
            r_esc = r.replace('\\', r'\\').replace('"', r'\\"')
            meta_lines.append(f'    reference_{i} = "{r_esc}"')

        # Add some IOC context in meta for traceability (first few items)
        for i, h in enumerate(sha256s[:5], 1):
            meta_lines.append(f'    sample_sha256_{i} = "{h}"')
        for i, h in enumerate(imphashes[:5], 1):
            meta_lines.append(f'    sample_imphash_{i} = "{h}"')

        # Assemble rule
        tag_str = " ".join(tags) if tags else "apt"
        body = []
        body.append(f"rule {rule_name} : {tag_str}")
        body.append("{")
        body.append("  meta:")
        body.extend(meta_lines)
        if str_lines:
            body.append("  strings:")
            body.extend(str_lines)
        body.append("  condition:")
        body.append(f"    {condition}")
        body.append("}")
        return "\n".join(body)


# ------------------------------ CLI ----------------------------------------

def write_example(path: Path) -> None:
    example = {
        "families": [
            {
                "name": "APT_FAMILY",
                "filetype": "pe",
                "tags": ["apt", "windows", "pe"],
                "references": ["https://example.tld/report"],
                "iocs": {
                    "sha256": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
                    "imphash": ["1a79a4d60de6718e8e5b326e338ae533"],
                    "imports": [
                        {"dll": "KERNEL32.dll", "func": "CreateFileA"},
                        {"func": "HttpOpenRequestA"}
                    ],
                    "sections": [
                        {"name": ".text", "min_entropy": 6.0}
                    ],
                    "strings": [
                        {"value": "Global\\\\APTMutex", "nocase": True, "wide": True, "fullword": True},
                        {"regex": "https?:\\\/\\/[a-z0-9_.-]+", "nocase": True},
                        {"hex": "90 90 E8 ?? ?? ?? 68"}
                    ],
                    "domains": ["c2.example.tld"],
                    "urls": ["http://c2.example.tld/upd"],
                    "mutex": ["Global\\\\APTMutex"],
                    "registry": ["HKCU\\\\Software\\\\BadKey"]
                }
            }
        ]
    }
    path.write_text(json.dumps(example, indent=2), encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate YARA rules for APT families from JSON/YAML/CSV IoCs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--in", dest="in_path", required=False, help="Input file (.json/.yaml/.yml/.csv)")
    p.add_argument("--out", dest="out_path", required=False, help="Output .yar file (default: stdout)")
    p.add_argument("--author", default=os.getenv("USER", "unknown"), help="Author meta field")
    p.add_argument("--version", default="1.0", help="Rule version tag")
    p.add_argument("--rule-prefix", default="APT", help="Prefix for rule names")
    p.add_argument("--min-strings", type=int, default=2, help="Require N of ($s*) to match")
    p.add_argument("--license", default=None, help="License text to include as comment")
    p.add_argument("--example", dest="example", metavar="PATH", help="Write an example JSON template to PATH and exit")

    args = p.parse_args(argv)

    if args.example:
        write_example(Path(args.example))
        print(f"Wrote example template to {args.example}")
        return 0

    if not args.in_path:
        p.error("--in is required unless --example is used")

    families = load_input(Path(args.in_path))
    if not families:
        print("No families found in input.", file=sys.stderr)
        return 2

    yb = YaraBuilder(
        author=args.author,
        version=args.version,
        rule_prefix=args.rule_prefix,
        min_strings=args.min_strings,
        license_text=args.license,
    )

    ruleset = yb.build_ruleset(families)

    if args.out_path:
        Path(args.out_path).write_text(ruleset, encoding="utf-8")
        print(f"Wrote {args.out_path} with {len(families)} rule(s)")
    else:
        sys.stdout.write(ruleset)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
