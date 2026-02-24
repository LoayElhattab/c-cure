import sys
from tree_sitter import Language, Parser
import tree_sitter_cpp

CPP_LANGUAGE = Language(tree_sitter_cpp.language())
parser = Parser(CPP_LANGUAGE)

def extract_functions(file_path: str) -> list[dict]:
    """
    Parse a C++ file and return a list of extracted functions.
    Each item: { name, code, start_line, end_line }
    """
    try:
        with open(file_path, 'rb') as f:
            source = f.read()
    except FileNotFoundError:
        return []

    tree = parser.parse(source)
    functions = []

    def visit(node, depth=0):
        # Handle regular functions and template functions
        if node.type in ('function_definition', 'template_declaration'):
            name = extract_name(node, source)
            if name:
                code = source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
                functions.append({
                    'name': name,
                    'code': code,
                    'start_line': node.start_point[0] + 1,
                    'end_line': node.end_point[0] + 1,
                })
            # Don't recurse into function bodies to avoid nested captures
            return

        for child in node.children:
            visit(child, depth + 1)

    visit(tree.root_node)
    return functions


def extract_name(node, source: bytes) -> str | None:
    """
    Extract the function name from a function_definition or template_declaration node.
    """
    # If it's a template, dig into the inner function_definition first
    if node.type == 'template_declaration':
        for child in node.children:
            if child.type == 'function_definition':
                return extract_name(child, source)
        return None

    # Walk children looking for a declarator
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
    output_path = sys.argv[1].replace('.cpp', '_functions.txt')

    with open(output_path, 'w', encoding='utf-8') as f:
        for fn in results:
            f.write(f"{'='*60}\n")
            f.write(f"Function : {fn['name']}\n")
            f.write(f"Lines    : {fn['start_line']} - {fn['end_line']}\n")
            f.write(f"{'='*60}\n")
            f.write(fn['code'])
            f.write('\n\n')

    print(f"Saved {len(results)} functions → {output_path}")