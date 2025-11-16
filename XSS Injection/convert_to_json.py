#!/usr/bin/env python3
"""
Script to convert XSS payloads from markdown files to JSON format
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any


def is_valid_xss_payload(line: str) -> bool:
    """Check if a line is a valid XSS payload"""
    # Skip empty lines, comments, and documentation
    if not line or line.startswith('//') or line.startswith('#') or line.startswith('/*'):
        return False

    # Skip lines that are clearly documentation
    if line.startswith('-') or line.startswith('*') or line.startswith('['):
        return False

    # Skip lines that contain common documentation words
    doc_words = ['you can', 'this is', 'codename:', 'example:', 'note:', 'payload replacing',
                 'simple script', 'for this reason', 'better to use', 'allows you',
                 'one-line http', 'can be used', 'requirements:', 'payload:', 'source:']
    if any(word in line.lower() for word in doc_words):
        return False

    # Skip lines that are just sentences/descriptions (contain spaces and common words)
    common_words = ['the', 'is', 'are', 'was', 'were', 'been', 'being', 'have', 'has', 'had',
                    'do', 'does', 'did', 'will', 'would', 'should', 'can', 'could', 'may',
                    'might', 'must', 'shall', 'a', 'an', 'and', 'or', 'but', 'if', 'because',
                    'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against',
                    'between', 'into', 'through', 'during', 'before', 'after', 'above', 'below']

    word_count = sum(1 for word in common_words if ' ' + word + ' ' in ' ' + line.lower() + ' ')
    if word_count >= 3:  # If it contains 3 or more common words, likely a sentence
        return False

    # Skip http/https links that are not part of payloads
    if line.startswith('http') and '<' not in line and 'javascript:' not in line.lower():
        return False

    # Skip lines that look like version numbers or identifiers
    if line.count('.') >= 2 and line.count('<') == 0:
        return False

    # Must contain at least one XSS indicator
    xss_indicators = [
        '<', '>', 'javascript:', 'onerror', 'onload', 'onclick',
        'alert', 'prompt', 'confirm', 'eval', 'script', 'svg',
        'img', 'iframe', 'body', 'div', 'data:', 'vbscript:'
    ]

    has_indicator = any(indicator in line.lower() for indicator in xss_indicators)

    # Additional check: if line has < or >, it's more likely to be a payload
    has_html_chars = '<' in line or '>' in line

    # If it has HTML characters, be more lenient
    if has_html_chars:
        return True

    # Otherwise, be more strict
    return has_indicator and '(' in line  # Likely contains function call


def extract_payloads_from_code_block(code_block: str, section_name: str) -> List[Dict[str, Any]]:
    """Extract individual payloads from a code block"""
    payloads = []
    lines = code_block.strip().split('\n')

    for line in lines:
        line = line.strip()

        # Validate if this is a real XSS payload
        if not is_valid_xss_payload(line):
            continue

        # Determine type and context based on the payload
        payload_type = determine_type(line, section_name)
        context = determine_context(line)
        severity = determine_severity(line)

        payload_obj = {
            "payload": line,
            "category": "xss",
            "metadata": {
                "type": payload_type,
                "context": context,
                "severity": severity,
                "source": section_name
            }
        }
        payloads.append(payload_obj)

    return payloads


def determine_type(payload: str, section: str) -> str:
    """Determine the type of XSS payload"""
    payload_lower = payload.lower()

    if 'polyglot' in section.lower():
        return 'polyglot'
    elif 'bypass' in section.lower():
        return 'bypass'
    elif '<script' in payload_lower:
        return 'script_tag'
    elif '<img' in payload_lower:
        return 'img_tag'
    elif '<svg' in payload_lower:
        return 'svg_tag'
    elif '<iframe' in payload_lower:
        return 'iframe'
    elif 'onerror' in payload_lower or 'onload' in payload_lower or 'onclick' in payload_lower:
        return 'event_handler'
    elif 'javascript:' in payload_lower:
        return 'javascript_uri'
    elif 'data:' in payload_lower:
        return 'data_uri'
    elif '<body' in payload_lower or '<div' in payload_lower:
        return 'html_element'
    else:
        return 'generic'


def determine_context(payload: str) -> str:
    """Determine the context where the payload works"""
    payload_lower = payload.lower()

    if 'href=' in payload_lower or 'src=' in payload_lower:
        return 'attribute'
    elif 'javascript:' in payload_lower:
        return 'href'
    elif '<script' in payload_lower:
        return 'script_tag'
    elif 'style' in payload_lower:
        return 'style'
    elif 'on' in payload_lower and '=' in payload_lower:
        return 'event_attribute'
    else:
        return 'html'


def determine_severity(payload: str) -> str:
    """Determine the severity of the payload"""
    payload_lower = payload.lower()

    # Critical if it can steal cookies or sensitive data
    if 'document.cookie' in payload_lower or 'fetch' in payload_lower:
        return 'critical'
    # High for most XSS payloads
    elif 'alert' in payload_lower or 'prompt' in payload_lower or 'confirm' in payload_lower:
        return 'high'
    # Medium for potential XSS
    else:
        return 'medium'


def parse_markdown_file(file_path: Path) -> List[Dict[str, Any]]:
    """Parse a markdown file and extract all payloads"""
    all_payloads = []

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract code blocks
    code_block_pattern = r'```(?:javascript|html|js|xml|svg|csharp|ps1)?\n(.*?)```'
    matches = re.findall(code_block_pattern, content, re.DOTALL)

    # Extract section headers for context
    current_section = file_path.stem

    # Find section headers
    section_pattern = r'^#+\s+(.+)$'
    sections = re.findall(section_pattern, content, re.MULTILINE)

    # Process code blocks
    for i, code_block in enumerate(matches):
        # Try to find the section this code block belongs to
        section_name = current_section
        if i < len(sections):
            section_name = sections[i] if i < len(sections) else current_section

        payloads = extract_payloads_from_code_block(code_block, section_name)
        all_payloads.extend(payloads)

    return all_payloads


def parse_text_file(file_path: Path) -> List[Dict[str, Any]]:
    """Parse a text file containing raw payloads"""
    all_payloads = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()

        # Validate if this is a real XSS payload
        if not is_valid_xss_payload(line):
            continue

        payload_type = determine_type(line, file_path.stem)
        context = determine_context(line)
        severity = determine_severity(line)

        payload_obj = {
            "payload": line,
            "category": "xss",
            "metadata": {
                "type": payload_type,
                "context": context,
                "severity": severity,
                "source": file_path.stem
            }
        }
        all_payloads.append(payload_obj)

    return all_payloads


def main():
    """Main function to convert all XSS payloads to JSON"""
    base_dir = Path(__file__).parent
    output_file = base_dir / 'xss_payloads.json'

    all_payloads = []

    # Process markdown files
    md_files = [
        'README.md',
        '1 - XSS Filter Bypass.md',
        '2 - XSS Polyglot.md',
        '3 - XSS Common WAF Bypass.md',
        '4 - CSP Bypass.md',
        '5 - XSS in Angular.md'
    ]

    for md_file in md_files:
        file_path = base_dir / md_file
        if file_path.exists():
            print(f"Processing {md_file}...")
            payloads = parse_markdown_file(file_path)
            all_payloads.extend(payloads)
            print(f"  Found {len(payloads)} payloads")

    # Process Intruders folder
    intruders_dir = base_dir / 'Intruders'
    if intruders_dir.exists():
        for txt_file in intruders_dir.glob('*.txt'):
            print(f"Processing {txt_file.name}...")
            payloads = parse_text_file(txt_file)
            all_payloads.extend(payloads)
            print(f"  Found {len(payloads)} payloads")

    # Remove duplicates while preserving order
    seen = set()
    unique_payloads = []
    for payload in all_payloads:
        payload_str = payload['payload']
        if payload_str not in seen:
            seen.add(payload_str)
            unique_payloads.append(payload)

    # Write to JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(unique_payloads, f, indent=2, ensure_ascii=False)

    print(f"\nTotal payloads: {len(all_payloads)}")
    print(f"Unique payloads: {len(unique_payloads)}")
    print(f"Output saved to: {output_file}")


if __name__ == '__main__':
    main()
