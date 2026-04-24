use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtractedFunction {
    #[serde(alias = "name")]
    pub function_name: String,
    pub code: String,
    pub start_line: i32,
    pub end_line: i32,
}

pub fn clean_code(code: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = code.chars().collect();
    let n = chars.len();
    let mut i = 0;

    while i < n {
        if chars[i] == '"' {
            let mut j = i + 1;
            while j < n {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            if j < n {
                result.push_str(&code[i..=j]);
            } else {
                result.push_str(&code[i..n]);
            }
            i = j + 1;
        } else if chars[i] == '\'' {
            let mut j = i + 1;
            while j < n {
                if chars[j] == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j] == '\'' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            if j < n {
                result.push_str(&code[i..=j]);
            } else {
                result.push_str(&code[i..n]);
            }
            i = j + 1;
        } else if i + 1 < n && chars[i] == '/' && chars[i + 1] == '*' {
            let mut j = i + 2;
            let mut closed = false;
            while j + 1 < n {
                if chars[j] == '*' && chars[j + 1] == '/' {
                    closed = true;
                    j += 2;
                    break;
                }
                j += 1;
            }
            if !closed {
                break;
            }
            result.push(' ');
            i = j + 2;
        } else if i + 1 < n && chars[i] == '/' && chars[i + 1] == '/' {
            let mut j = i + 2;
            while j < n {
                if chars[j] == '\n' {
                    break;
                }
                j += 1;
            }
            if j < n {
                result.push('\n');
                i = j + 1;
            } else {
                break;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    let re_blank = Regex::new(r"\n{3,}").unwrap();
    let stripped = re_blank.replace_all(&result, "\n\n");

    let re_space = Regex::new(r"[ \t]+").unwrap();
    let stripped = re_space.replace_all(&stripped, " ");

    let lines: Vec<&str> = stripped.lines().map(|l| l.trim_end()).collect();
    lines.join("\n").trim().to_string()
}

pub fn extract_functions(file_path: &str) -> std::io::Result<Vec<ExtractedFunction>> {
    let source = fs::read(file_path)?;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::language())
        .expect("Error loading C++ grammar");

    let tree = parser.parse(&source, None).unwrap();
    let mut functions = Vec::new();

    fn visit(node: tree_sitter::Node, source: &[u8], functions: &mut Vec<ExtractedFunction>) {
        if node.kind() == "function_definition" || node.kind() == "template_declaration" {
            if let Some(name) = extract_name(node, source) {
                let start_byte = node.start_byte();
                let end_byte = node.end_byte();
                let raw_code = String::from_utf8_lossy(&source[start_byte..end_byte]).to_string();
                functions.push(ExtractedFunction {
                    function_name: name,
                    code: clean_code(&raw_code),
                    start_line: (node.start_position().row + 1) as i32,
                    end_line: (node.end_position().row + 1) as i32,
                });
            }
            return;
        }

        let mut walker = node.walk();
        for child in node.children(&mut walker) {
            visit(child, source, functions);
        }
    }

    fn extract_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
        if node.kind() == "template_declaration" {
            let mut walker = node.walk();
            for child in node.children(&mut walker) {
                if child.kind() == "function_definition" {
                    return extract_name(child, source);
                }
            }
            return None;
        }

        let mut walker = node.walk();
        for child in node.children(&mut walker) {
            let kind = child.kind();
            if kind == "function_declarator"
                || kind == "pointer_declarator"
                || kind == "reference_declarator"
            {
                return extract_name(child, source);
            }
            if kind == "qualified_identifier" || kind == "identifier" || kind == "field_identifier"
            {
                return Some(
                    String::from_utf8_lossy(&source[child.start_byte()..child.end_byte()])
                        .to_string(),
                );
            }
        }
        None
    }

    visit(tree.root_node(), &source, &mut functions);
    Ok(functions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_clean_code_comments() {
        let input =
            "void main() {\n  // single line\n  int a = 1; /* multi\n  line */\n  return 0;\n}";
        // The regexes collapse whitespace and handle line breaks.
        // "// single line" + newline results in a double newline.
        // Multiple spaces are collapsed.
        let expected = "void main() {\n\n int a = 1; return 0;\n}";
        assert_eq!(clean_code(input), expected);
    }

    #[test]
    fn test_clean_code_strings() {
        let input = "string s = \"do not // remove this\"; // but remove this";
        let cleaned = clean_code(input);
        assert!(cleaned.contains("\"do not // remove this\""));
        assert!(!cleaned.contains("but remove this"));
    }

    #[test]
    fn test_extract_functions_simple() -> std::io::Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "int add(int a, int b) {{ return a + b; }}")?;

        let functions = extract_functions(file.path().to_str().unwrap())?;
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].function_name, "add");
        assert!(functions[0].code.contains("return a + b;"));
        Ok(())
    }

    #[test]
    fn test_extract_functions_template() -> std::io::Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(
            file,
            "template <typename T>\nT sum(T a, T b) {{ return a + b; }}"
        )?;

        let functions = extract_functions(file.path().to_str().unwrap())?;
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].function_name, "sum");
        Ok(())
    }
}
