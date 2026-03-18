#!/usr/bin/env python3
"""
PayloadsAllTheThings Integration Tool (PATT)

A CLI tool for searching, browsing, and extracting payloads from
the PayloadsAllTheThings repository. Designed for authorized
penetration testing and security research.

Usage:
    python3 patt.py list                          # List all categories
    python3 patt.py info <category>               # Show category details
    python3 patt.py search <keyword>              # Search across all content
    python3 patt.py payloads <category>           # Extract payloads from a category
    python3 patt.py wordlists <category>          # List available wordlist files
    python3 patt.py dump <category> [--wordlist]  # Dump payloads to stdout (pipe-friendly)
    python3 patt.py techniques                    # List methodology/resource guides
    python3 patt.py techniques <topic>            # Show a specific technique guide
"""

import argparse
import os
import re
import sys
from pathlib import Path

# Resolve repo root relative to this script
REPO_ROOT = Path(__file__).resolve().parent

# Directories to skip when listing categories
SKIP_DIRS = {
    ".git", ".github", "_LEARNING_AND_SOCIALS", "_template_vuln",
    "__pycache__", ".workflows", "overrides",
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def get_categories():
    """Return sorted list of vulnerability category directory names."""
    cats = []
    for entry in sorted(REPO_ROOT.iterdir()):
        if entry.is_dir() and entry.name not in SKIP_DIRS and not entry.name.startswith("."):
            if entry.name == "Methodology and Resources":
                continue  # handled separately via 'techniques'
            cats.append(entry.name)
    return cats


def resolve_category(name):
    """Fuzzy-match a category name (case-insensitive substring)."""
    name_lower = name.lower()
    categories = get_categories()
    # Exact match first
    for cat in categories:
        if cat.lower() == name_lower:
            return cat
    # Substring match
    matches = [c for c in categories if name_lower in c.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"Ambiguous category '{name}'. Did you mean one of:")
        for m in matches:
            print(f"  - {m}")
        sys.exit(1)
    print(f"Category '{name}' not found. Use 'list' to see available categories.")
    sys.exit(1)


def extract_code_blocks(md_text):
    """Extract all fenced code blocks from markdown text."""
    pattern = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)
    return pattern.findall(md_text)


def extract_inline_payloads(md_text):
    """Extract inline code snippets (backtick-wrapped) from markdown."""
    return re.findall(r"`([^`\n]{3,})`", md_text)


def colorize(text, color):
    """Apply ANSI color if stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    colors = {
        "bold": "\033[1m",
        "green": "\033[32m",
        "cyan": "\033[36m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "magenta": "\033[35m",
        "reset": "\033[0m",
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def print_header(text):
    print(f"\n{colorize(text, 'bold')}")
    print(colorize("─" * min(len(text), 60), "cyan"))


def count_lines(filepath):
    """Count non-empty lines in a file."""
    try:
        with open(filepath, "r", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


# ── Commands ─────────────────────────────────────────────────────────────────

def cmd_list(args):
    """List all vulnerability categories."""
    categories = get_categories()
    print_header(f"PayloadsAllTheThings — {len(categories)} Categories")
    for i, cat in enumerate(categories, 1):
        cat_path = REPO_ROOT / cat
        has_readme = (cat_path / "README.md").exists()
        intruder_dir = cat_path / "Intruder"
        if not intruder_dir.exists():
            intruder_dir = cat_path / "Intruders"
        wordlist_count = len(list(intruder_dir.glob("*.txt"))) if intruder_dir.exists() else 0

        status = []
        if has_readme:
            status.append("docs")
        if wordlist_count:
            status.append(f"{wordlist_count} wordlists")

        tags = colorize(f"[{', '.join(status)}]", "cyan") if status else ""
        print(f"  {i:2d}. {cat} {tags}")


def cmd_info(args):
    """Show detailed info about a category."""
    cat = resolve_category(args.category)
    cat_path = REPO_ROOT / cat

    print_header(cat)

    readme = cat_path / "README.md"
    if readme.exists():
        text = readme.read_text(errors="replace")
        # Extract summary / table of contents
        lines = text.split("\n")
        # Print first few meaningful lines as description
        desc_lines = []
        for line in lines:
            if line.startswith("#"):
                continue
            if line.strip().startswith(">"):
                desc_lines.append(line.strip().lstrip("> "))
            elif line.strip().startswith("- ["):
                desc_lines.append(line.strip())
            if len(desc_lines) > 20:
                break

        if desc_lines:
            print(colorize("\nDescription / Contents:", "yellow"))
            for dl in desc_lines:
                print(f"  {dl}")

        # Count code blocks
        blocks = extract_code_blocks(text)
        print(f"\n  Code blocks with payloads: {colorize(str(len(blocks)), 'green')}")
        print(f"  Document size: {len(lines)} lines")

    # Sub-documents
    sub_mds = [f for f in cat_path.glob("*.md") if f.name != "README.md"]
    if sub_mds:
        print(colorize("\nSub-guides:", "yellow"))
        for md in sorted(sub_mds):
            print(f"  - {md.name}")

    # Wordlists
    intruder_dir = cat_path / "Intruder"
    if not intruder_dir.exists():
        intruder_dir = cat_path / "Intruders"
    if intruder_dir.exists():
        txt_files = sorted(intruder_dir.glob("*.txt"))
        if txt_files:
            print(colorize("\nWordlists (Intruder):", "yellow"))
            for tf in txt_files:
                lc = count_lines(tf)
                print(f"  - {tf.name} ({lc} payloads)")

    # Scripts
    scripts = list(cat_path.rglob("*.py")) + list(cat_path.rglob("*.sh")) + \
              list(cat_path.rglob("*.rb")) + list(cat_path.rglob("*.js"))
    if scripts:
        print(colorize("\nScripts/Tools:", "yellow"))
        for s in sorted(scripts):
            rel = s.relative_to(cat_path)
            print(f"  - {rel}")

    # Subdirectories
    subdirs = [d for d in cat_path.iterdir()
               if d.is_dir() and d.name not in ("Images", "Intruder", "Intruders", "Files", "__pycache__")]
    if subdirs:
        print(colorize("\nSubcategories:", "yellow"))
        for sd in sorted(subdirs):
            print(f"  - {sd.name}")


def cmd_search(args):
    """Search across all categories for a keyword."""
    keyword = args.keyword
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    results = []

    # Search markdown files
    for md_file in REPO_ROOT.rglob("*.md"):
        if ".git" in md_file.parts:
            continue
        try:
            text = md_file.read_text(errors="replace")
        except Exception:
            continue
        matches = []
        for i, line in enumerate(text.split("\n"), 1):
            if pattern.search(line):
                matches.append((i, line.strip()))
        if matches:
            results.append((md_file, matches))

    # Search payload txt files
    for txt_file in REPO_ROOT.rglob("*.txt"):
        if ".git" in txt_file.parts:
            continue
        try:
            text = txt_file.read_text(errors="replace")
        except Exception:
            continue
        matches = []
        for i, line in enumerate(text.split("\n"), 1):
            if pattern.search(line):
                matches.append((i, line.strip()))
        if matches:
            results.append((txt_file, matches))

    if not results:
        print(f"No results for '{keyword}'.")
        return

    print_header(f"Search results for '{keyword}' — {sum(len(m) for _, m in results)} matches in {len(results)} files")

    max_results = args.limit
    shown = 0
    for filepath, matches in results:
        rel = filepath.relative_to(REPO_ROOT)
        print(f"\n{colorize(str(rel), 'green')}")
        for lineno, line in matches[:5]:
            # Highlight the keyword in the line
            highlighted = pattern.sub(
                lambda m: colorize(m.group(), "red") if sys.stdout.isatty() else m.group(),
                line
            )
            print(f"  {colorize(str(lineno), 'cyan'):>6}: {highlighted[:200]}")
        if len(matches) > 5:
            print(f"  ... and {len(matches) - 5} more matches")
        shown += 1
        if shown >= max_results:
            remaining = len(results) - shown
            if remaining > 0:
                print(f"\n  ... {remaining} more files (use --limit to show more)")
            break


def cmd_payloads(args):
    """Extract and display payloads from a category's documentation."""
    cat = resolve_category(args.category)
    cat_path = REPO_ROOT / cat

    # Collect from all markdown files in the category
    md_files = sorted(cat_path.glob("*.md"))
    if not md_files:
        print(f"No documentation found for '{cat}'.")
        return

    total_blocks = 0
    for md_file in md_files:
        text = md_file.read_text(errors="replace")
        blocks = extract_code_blocks(text)
        if not blocks:
            continue

        print_header(f"Payloads from {md_file.name}")
        for i, block in enumerate(blocks, 1):
            block = block.strip()
            if not block:
                continue
            total_blocks += 1
            print(f"\n{colorize(f'[{i}]', 'yellow')}")
            # Truncate very long blocks in interactive mode
            lines = block.split("\n")
            if len(lines) > 30 and sys.stdout.isatty():
                for line in lines[:25]:
                    print(f"  {line}")
                print(f"  {colorize(f'... ({len(lines) - 25} more lines)', 'cyan')}")
            else:
                for line in lines:
                    print(f"  {line}")

    if total_blocks == 0:
        print("No code block payloads found. Try 'wordlists' or 'dump' instead.")
    else:
        print(f"\n{colorize(f'Total: {total_blocks} payload blocks', 'bold')}")


def cmd_wordlists(args):
    """List and optionally display wordlist files for a category."""
    cat = resolve_category(args.category)
    cat_path = REPO_ROOT / cat

    intruder_dir = cat_path / "Intruder"
    if not intruder_dir.exists():
        intruder_dir = cat_path / "Intruders"

    if not intruder_dir.exists():
        print(f"No wordlist/intruder directory found for '{cat}'.")
        return

    txt_files = sorted(intruder_dir.glob("*.txt"))
    if not txt_files:
        print(f"No wordlist files found in {intruder_dir}.")
        return

    print_header(f"Wordlists for {cat}")
    for tf in txt_files:
        lc = count_lines(tf)
        print(f"\n  {colorize(tf.name, 'green')} — {lc} payloads")
        # Show first few lines as preview
        if sys.stdout.isatty():
            with open(tf, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= 5:
                        print(f"    {colorize('...', 'cyan')}")
                        break
                    print(f"    {line.rstrip()}")


def cmd_dump(args):
    """Dump payloads to stdout — pipe-friendly, no formatting."""
    cat = resolve_category(args.category)
    cat_path = REPO_ROOT / cat

    if args.wordlist:
        # Dump all wordlist files
        intruder_dir = cat_path / "Intruder"
        if not intruder_dir.exists():
            intruder_dir = cat_path / "Intruders"
        if not intruder_dir.exists():
            print(f"No wordlist directory for '{cat}'.", file=sys.stderr)
            sys.exit(1)
        for tf in sorted(intruder_dir.glob("*.txt")):
            with open(tf, "r", errors="replace") as f:
                for line in f:
                    stripped = line.rstrip("\n\r")
                    if stripped:
                        print(stripped)
    else:
        # Dump code blocks from markdown
        for md_file in sorted(cat_path.glob("*.md")):
            text = md_file.read_text(errors="replace")
            for block in extract_code_blocks(text):
                block = block.strip()
                if block:
                    print(block)
                    print()  # separator between blocks


def cmd_techniques(args):
    """List or display methodology and resource guides."""
    meth_dir = REPO_ROOT / "Methodology and Resources"
    if not meth_dir.exists():
        print("Methodology and Resources directory not found.")
        return

    guides = sorted(meth_dir.glob("*.md"))

    if args.topic:
        # Fuzzy match topic
        topic_lower = args.topic.lower()
        matches = [g for g in guides if topic_lower in g.stem.lower()]
        if not matches:
            print(f"No technique guide matching '{args.topic}'.")
            print("Available guides:")
            for g in guides:
                print(f"  - {g.stem}")
            return
        if len(matches) > 1:
            # Show all matches with first lines
            print(f"Multiple matches for '{args.topic}':")
            for m in matches:
                print(f"  - {m.stem}")
            return

        guide = matches[0]
        text = guide.read_text(errors="replace")
        print_header(guide.stem)
        # Print with pagination hint
        lines = text.split("\n")
        for line in lines:
            print(line)
    else:
        print_header(f"Methodology & Resources — {len(guides)} Guides")
        for i, g in enumerate(guides, 1):
            print(f"  {i:2d}. {g.stem}")
        print(f"\nUsage: patt.py techniques <topic>")
        print(f"Example: patt.py techniques 'reverse shell'")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="patt",
        description="PayloadsAllTheThings Integration Tool — search, browse, and extract payloads",
        epilog="For authorized security testing and research only.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list
    subparsers.add_parser("list", help="List all vulnerability categories")

    # info
    p_info = subparsers.add_parser("info", help="Show details about a category")
    p_info.add_argument("category", help="Category name (fuzzy match)")

    # search
    p_search = subparsers.add_parser("search", help="Search across all content")
    p_search.add_argument("keyword", help="Keyword to search for")
    p_search.add_argument("--limit", type=int, default=20, help="Max files to show (default: 20)")

    # payloads
    p_payloads = subparsers.add_parser("payloads", help="Extract payloads from category docs")
    p_payloads.add_argument("category", help="Category name (fuzzy match)")

    # wordlists
    p_wordlists = subparsers.add_parser("wordlists", help="Show wordlist files for a category")
    p_wordlists.add_argument("category", help="Category name (fuzzy match)")

    # dump
    p_dump = subparsers.add_parser("dump", help="Dump payloads to stdout (pipe-friendly)")
    p_dump.add_argument("category", help="Category name (fuzzy match)")
    p_dump.add_argument("--wordlist", "-w", action="store_true", help="Dump wordlist files instead of code blocks")

    # techniques
    p_tech = subparsers.add_parser("techniques", help="Browse methodology and resource guides")
    p_tech.add_argument("topic", nargs="?", help="Topic to look up (fuzzy match)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "list": cmd_list,
        "info": cmd_info,
        "search": cmd_search,
        "payloads": cmd_payloads,
        "wordlists": cmd_wordlists,
        "dump": cmd_dump,
        "techniques": cmd_techniques,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
