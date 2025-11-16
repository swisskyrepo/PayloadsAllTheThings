#!/usr/bin/env python3
"""
Script to convert SQL Injection payloads from markdown files to JSON format
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any


def is_valid_sqli_payload(line: str) -> bool:
    """Check if a line is a valid SQL injection payload"""
    # Skip empty lines, comments, and documentation
    if not line or line.startswith('//') or line.startswith('#') or line.startswith('/*'):
        return False

    # Skip lines that are clearly documentation
    if line.startswith('-') or line.startswith('*') or line.startswith('['):
        return False

    # Skip lines that contain common documentation words
    doc_words = ['you can', 'this is', 'example:', 'note:', 'payload:', 'source:',
                 'allows you', 'can be used', 'requirements:', 'description:',
                 'using this', 'this will', 'for example', 'such as']
    if any(word in line.lower() for word in doc_words):
        return False

    # Skip lines that are just sentences/descriptions
    common_words = ['the', 'is', 'are', 'was', 'were', 'been', 'being', 'have', 'has', 'had',
                    'do', 'does', 'did', 'will', 'would', 'should', 'can', 'could', 'may',
                    'might', 'must', 'shall', 'a', 'an', 'and', 'or', 'but', 'if', 'because',
                    'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against',
                    'between', 'into', 'through', 'during', 'before', 'after', 'above', 'below']

    word_count = sum(1 for word in common_words if ' ' + word + ' ' in ' ' + line.lower() + ' ')
    if word_count >= 3:  # If it contains 3 or more common words, likely a sentence
        return False

    # Skip http/https links that are not part of payloads
    if line.startswith('http') and 'select' not in line.lower() and 'union' not in line.lower():
        return False

    # Skip table headers and separators
    if line.startswith('|') or line.count('|') >= 3:
        return False

    # Must contain at least one SQL injection indicator
    sqli_indicators = [
        'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
        'alter', 'exec', 'execute', 'declare', 'cast', 'convert', 'concat',
        'substring', 'sleep', 'benchmark', 'waitfor', 'delay', 'pg_sleep',
        'dbms_', 'utl_', 'xp_', 'sp_', 'sys.', 'information_schema',
        'having', 'group by', 'order by', 'limit', 'offset', 'where',
        '@@', 'schema', 'database', 'table', 'column', 'char(', 'chr(',
        'ascii', 'hex', 'unhex', 'load_file', 'into outfile', 'dumpfile',
        "' or ", '" or ', '-- ', '#', '/*', '*/', 'null', 'version()'
    ]

    has_indicator = any(indicator in line.lower() for indicator in sqli_indicators)

    # SQL payloads often contain SQL syntax characters
    has_sql_chars = any(char in line for char in ["'", '"', '--', '/*', ';', '='])

    # Additional checks for common SQL patterns
    sql_patterns = [
        r"'\s+or\s+", r'"\s+or\s+', r'1\s*=\s*1', r'1\s*=\s*2',
        r'union\s+select', r'union\s+all', r'and\s+1\s*=',
        r'admin\'', r'\'--', r'\'#', r'\) or ', r'\) and '
    ]

    has_sql_pattern = any(re.search(pattern, line, re.IGNORECASE) for pattern in sql_patterns)

    return has_indicator or has_sql_chars or has_sql_pattern


def extract_payloads_from_code_block(code_block: str, section_name: str, db_type: str = "generic") -> List[Dict[str, Any]]:
    """Extract individual SQL injection payloads from a code block"""
    payloads = []
    lines = code_block.strip().split('\n')

    for line in lines:
        line = line.strip()

        # Validate if this is a real SQL injection payload
        if not is_valid_sqli_payload(line):
            continue

        # Determine type and context based on the payload
        payload_type = determine_type(line, section_name)
        technique = determine_technique(line)
        severity = determine_severity(line)

        payload_obj = {
            "payload": line,
            "category": "sqli",
            "metadata": {
                "type": payload_type,
                "technique": technique,
                "dbms": db_type,
                "severity": severity,
                "source": section_name
            }
        }
        payloads.append(payload_obj)

    return payloads


def determine_type(payload: str, section: str) -> str:
    """Determine the type of SQL injection payload"""
    payload_lower = payload.lower()
    section_lower = section.lower()

    if 'auth' in section_lower or 'bypass' in section_lower:
        return 'authentication_bypass'
    elif 'union' in payload_lower:
        return 'union_based'
    elif 'error' in section_lower:
        return 'error_based'
    elif 'blind' in section_lower or 'time' in section_lower:
        return 'blind'
    elif 'sleep' in payload_lower or 'benchmark' in payload_lower or 'waitfor' in payload_lower or 'pg_sleep' in payload_lower:
        return 'time_based'
    elif 'boolean' in section_lower:
        return 'boolean_based'
    elif 'stacked' in section_lower:
        return 'stacked_queries'
    elif 'polyglot' in section_lower:
        return 'polyglot'
    elif 'out of band' in section_lower or 'oast' in section_lower:
        return 'out_of_band'
    else:
        return 'generic'


def determine_technique(payload: str) -> str:
    """Determine the SQL injection technique"""
    payload_lower = payload.lower()

    if 'union' in payload_lower and 'select' in payload_lower:
        return 'union_select'
    elif any(keyword in payload_lower for keyword in ['sleep', 'benchmark', 'waitfor', 'pg_sleep', 'dbms_lock']):
        return 'time_delay'
    elif "' or " in payload_lower or '" or ' in payload_lower or '1=1' in payload_lower:
        return 'boolean_logic'
    elif 'extractvalue' in payload_lower or 'updatexml' in payload_lower or 'xmltype' in payload_lower:
        return 'xml_error'
    elif 'load_file' in payload_lower or 'into outfile' in payload_lower or 'into dumpfile' in payload_lower:
        return 'file_operation'
    elif 'exec' in payload_lower or 'execute' in payload_lower or 'xp_cmdshell' in payload_lower:
        return 'command_execution'
    elif 'cast' in payload_lower or 'convert' in payload_lower:
        return 'type_conversion'
    else:
        return 'basic'


def determine_severity(payload: str) -> str:
    """Determine the severity of the SQL injection payload"""
    payload_lower = payload.lower()

    # Critical if it involves command execution or file operations
    if any(keyword in payload_lower for keyword in ['xp_cmdshell', 'exec', 'execute', 'load_file', 'into outfile', 'into dumpfile']):
        return 'critical'
    # High for data extraction
    elif any(keyword in payload_lower for keyword in ['union select', 'information_schema', 'sys.', 'database()', 'version()']):
        return 'high'
    # Medium for authentication bypass
    elif "' or " in payload_lower or '" or ' in payload_lower or '1=1' in payload_lower:
        return 'high'
    # Medium for blind injection
    elif any(keyword in payload_lower for keyword in ['sleep', 'benchmark', 'waitfor', 'pg_sleep']):
        return 'medium'
    else:
        return 'medium'


def parse_markdown_file(file_path: Path) -> List[Dict[str, Any]]:
    """Parse a markdown file and extract all SQL injection payloads"""
    all_payloads = []

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Determine database type from filename
    db_type = "generic"
    if 'mysql' in file_path.name.lower():
        db_type = "mysql"
    elif 'mssql' in file_path.name.lower():
        db_type = "mssql"
    elif 'postgresql' in file_path.name.lower():
        db_type = "postgresql"
    elif 'oracle' in file_path.name.lower():
        db_type = "oracle"
    elif 'sqlite' in file_path.name.lower():
        db_type = "sqlite"
    elif 'db2' in file_path.name.lower():
        db_type = "db2"
    elif 'cassandra' in file_path.name.lower():
        db_type = "cassandra"
    elif 'bigquery' in file_path.name.lower():
        db_type = "bigquery"

    # Extract code blocks
    code_block_pattern = r'```(?:sql|bash|ps1|sh)?\n(.*?)```'
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

        payloads = extract_payloads_from_code_block(code_block, section_name, db_type)
        all_payloads.extend(payloads)

    return all_payloads


def parse_text_file(file_path: Path) -> List[Dict[str, Any]]:
    """Parse a text file containing raw SQL injection payloads"""
    all_payloads = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # Determine database type from filename
    db_type = "generic"
    filename_lower = file_path.name.lower()
    if 'mysql' in filename_lower:
        db_type = "mysql"
    elif 'mssql' in filename_lower:
        db_type = "mssql"
    elif 'postgres' in filename_lower:
        db_type = "postgresql"
    elif 'oracle' in filename_lower:
        db_type = "oracle"

    for line in lines:
        line = line.strip()

        # Validate if this is a real SQL injection payload
        if not is_valid_sqli_payload(line):
            continue

        payload_type = determine_type(line, file_path.stem)
        technique = determine_technique(line)
        severity = determine_severity(line)

        payload_obj = {
            "payload": line,
            "category": "sqli",
            "metadata": {
                "type": payload_type,
                "technique": technique,
                "dbms": db_type,
                "severity": severity,
                "source": file_path.stem
            }
        }
        all_payloads.append(payload_obj)

    return all_payloads


def main():
    """Main function to convert all SQL injection payloads to JSON"""
    base_dir = Path(__file__).parent
    output_file = base_dir / 'sqli_payloads.json'

    all_payloads = []

    # Process markdown files
    md_files = [
        'README.md',
        'MySQL Injection.md',
        'MSSQL Injection.md',
        'PostgreSQL Injection.md',
        'OracleSQL Injection.md',
        'SQLite Injection.md',
        'DB2 Injection.md',
        'Cassandra Injection.md',
        'BigQuery Injection.md'
    ]

    for md_file in md_files:
        file_path = base_dir / md_file
        if file_path.exists():
            print(f"Processing {md_file}...")
            payloads = parse_markdown_file(file_path)
            all_payloads.extend(payloads)
            print(f"  Found {len(payloads)} payloads")

    # Process Intruder folder
    intruder_dir = base_dir / 'Intruder'
    if intruder_dir.exists():
        for txt_file in intruder_dir.iterdir():
            if txt_file.is_file():
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
