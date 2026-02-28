import re
import sys
from tree_sitter import Language, Parser
import tree_sitter_cpp

CPP_LANGUAGE = Language(tree_sitter_cpp.language())
parser = Parser(CPP_LANGUAGE)


def clean_code(code: str) -> str:
    """
    Strip single-line and multi-line comments, then normalize whitespace.
    Preserves string literals — does NOT strip // or /* inside strings.
    Used to clean code before sending to ML inference.
    Line numbers are NOT affected — this is only applied to the code field.
    """
    result = []
    i = 0
    n = len(code)

    while i < n:
        # String literal — copy verbatim, don't strip inside
        if code[i] == '"':
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == '"':
                    j += 1
                    break
                j += 1
            result.append(code[i:j])
            i = j

        # Char literal — copy verbatim
        elif code[i] == "'":
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == "'":
                    j += 1
                    break
                j += 1
            result.append(code[i:j])
            i = j

        # Multi-line comment /* ... */
        elif code[i:i+2] == '/*':
            j = code.find('*/', i + 2)
            if j == -1:
                break  # unclosed comment, skip rest
            # Replace with single space to avoid joining tokens
            result.append(' ')
            i = j + 2

        # Single-line comment // ...
        elif code[i:i+2] == '//':
            j = code.find('\n', i + 2)
            if j == -1:
                break  # comment runs to EOF
            # Preserve the newline so line structure is maintained
            result.append('\n')
            i = j + 1

        else:
            result.append(code[i])
            i += 1

    stripped = ''.join(result)

    # Normalize: collapse multiple blank lines into one
    stripped = re.sub(r'\n{3,}', '\n\n', stripped)

    # Normalize: collapse multiple spaces/tabs into one (but not newlines)
    stripped = re.sub(r'[ \t]+', ' ', stripped)

    # Strip trailing whitespace on each line
    stripped = '\n'.join(line.rstrip() for line in stripped.splitlines())

    # Remove leading/trailing blank lines
    stripped = stripped.strip()

    return stripped


def extract_functions(file_path: str) -> list[dict]:
    """
    Parse a C++ file and return a list of extracted functions.
    Each item: { name, code, start_line, end_line }
    - code is cleaned (comments stripped, whitespace normalized) for ML inference
    - start_line / end_line are from the original source for accurate report display
    """
    try:
        with open(file_path, 'rb') as f:
            source = f.read()
    except FileNotFoundError:
        return []

    tree = parser.parse(source)
    functions = []

    def visit(node, depth=0):
        if node.type in ('function_definition', 'template_declaration'):
            name = extract_name(node, source)
            if name:
                raw_code = source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
                functions.append({
                    'name':       name,
                    'code':       clean_code(raw_code),  # ← cleaned for ML
                    'start_line': node.start_point[0] + 1,
                    'end_line':   node.end_point[0] + 1,
                })
            return  # don't recurse into function bodies

        for child in node.children:
            visit(child, depth + 1)

    visit(tree.root_node)
    return functions


def extract_name(node, source: bytes) -> str | None:
    """
    Extract the function name from a function_definition or template_declaration node.
    """
    if node.type == 'template_declaration':
        for child in node.children:
            if child.type == 'function_definition':
                return extract_name(child, source)
        return None

    for child in node.children:
        if child.type in ('function_declarator', 'pointer_declarator', 'reference_declarator'):
            return extract_name(child, source)
        if child.type == 'qualified_identifier':
            return source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
        if child.type == 'identifier':
            return source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')

    return None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python parser.py <file.cpp>")
        sys.exit(1)

    results = extract_functions(sys.argv[1])
    print(f"Found {len(results)} functions:\n")
    for fn in results:
        print(f"  [{fn['start_line']}-{fn['end_line']}] {fn['name']}")
        print(f"  {'-'*40}")
        print(f"  {fn['code'][:120].strip()}...")
        print()