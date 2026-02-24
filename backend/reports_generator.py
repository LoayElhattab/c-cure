"""
Merged seed script: runs all three seeding operations (single‑file, multi‑file, and multi‑CWE) for UI testing.
Usage: python merged_seed.py
"""
import json
from database import db

def seed_single_file():
    """Original seed.py: single file with multiple vulnerabilities."""
    PROJECT = "test_vulnerable.cpp"
    BASE = "C:/Users/test/Desktop/test_vulnerable.cpp"

    aid = db.save_analysis(PROJECT, BASE)
    fid = db.save_file(aid, BASE)

    functions = [
        {
            "name": "readBuffer", "code": "void readBuffer(char* buf, int len) {\n    for (int i = 0; i <= len; i++) {\n        printf(\"%c\", buf[i]);\n    }\n}",
            "verdict": "vulnerable", "cwe": "CWE-125", "cwe_name": "Out-of-bounds Read",
            "severity": "High", "confidence": 0.91, "start_line": 6, "end_line": 10,
        },
        {
            "name": "copyData", "code": "void copyData(char* dst, char* src) {\n    strcpy(dst, src);\n}",
            "verdict": "vulnerable", "cwe": "CWE-787", "cwe_name": "Out-of-bounds Write",
            "severity": "Critical", "confidence": 0.88, "start_line": 13, "end_line": 15,
        },
        {
            "name": "calculateSize", "code": "int calculateSize(int a, int b) {\n    int result = a * b;\n    return result;\n}",
            "verdict": "vulnerable", "cwe": "CWE-190", "cwe_name": "Integer Overflow",
            "severity": "Medium", "confidence": 0.76, "start_line": 18, "end_line": 21,
        },
        {
            "name": "divide", "code": "float divide(float a, float b) {\n    return a / b;\n}",
            "verdict": "vulnerable", "cwe": "CWE-369", "cwe_name": "Divide By Zero",
            "severity": "Medium", "confidence": 0.83, "start_line": 24, "end_line": 26,
        },
        {
            "name": "processData", "code": "void processData(char* data) {\n    char* buf = (char*)malloc(100);\n    free(buf);\n    free(buf);\n}",
            "verdict": "vulnerable", "cwe": "CWE-415", "cwe_name": "Double Free",
            "severity": "High", "confidence": 0.95, "start_line": 29, "end_line": 33,
        },
        {
            "name": "getLength", "code": "int getLength(char* str) {\n    return strlen(str);\n}",
            "verdict": "vulnerable", "cwe": "CWE-476", "cwe_name": "NULL Pointer Dereference",
            "severity": "High", "confidence": 0.79, "start_line": 36, "end_line": 38,
        },
        {
            "name": "add", "code": "int add(int a, int b) {\n    return a + b;\n}",
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": 0.97, "start_line": 41, "end_line": 43,
        },
        {
            "name": "printMessage", "code": "void printMessage(const char* msg) {\n    if (msg != nullptr) {\n        printf(\"%s\\n\", msg);\n    }\n}",
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": 0.99, "start_line": 46, "end_line": 50,
        },
    ]

    for fn in functions:
        db.save_function(fid, fn)

    print(f"✓ Seeded single‑file analysis — ID {aid}")
    print(f"  Project : {PROJECT}")
    print(f"  Functions: {len(functions)}  |  Vulnerable: {sum(1 for f in functions if f['verdict'] == 'vulnerable')}  |  Safe: {sum(1 for f in functions if f['verdict'] == 'safe')}")
    print(f"  Navigate to: /report/{aid}\n")

def seed_multi_file():
    """Original multi-seed.py: multi‑file project with mixed vulnerabilities."""
    PROJECT = "network_utils"
    BASE = "C:/Users/test/Desktop/network_utils"

    aid = db.save_analysis(PROJECT, BASE)

    # File 1: socket.cpp
    fid1 = db.save_file(aid, f"{BASE}/src/network/socket.cpp")
    for fn in [
        {
            "name": "recv_data",
            "code": 'int recv_data(int sock, char* buf, int len) {\n    char tmp[64];\n    int n = recv(sock, tmp, len, 0);\n    memcpy(buf, tmp, n);\n    return n;\n}',
            "verdict": "vulnerable", "cwe": "CWE-787", "cwe_name": "Out-of-bounds Write",
            "severity": "Critical", "confidence": None, "start_line": 8, "end_line": 14,
        },
        {
            "name": "parse_header",
            "code": 'void parse_header(char* raw, Header* out) {\n    char key[32];\n    sscanf(raw, "%s: %s", key, out->value);\n}',
            "verdict": "vulnerable", "cwe": "CWE-125", "cwe_name": "Out-of-bounds Read",
            "severity": "High", "confidence": None, "start_line": 17, "end_line": 21,
        },
        {
            "name": "close_socket",
            "code": 'void close_socket(int sock) {\n    if (sock >= 0)\n        close(sock);\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 24, "end_line": 27,
        },
        {
            "name": "create_socket",
            "code": 'int create_socket(int port) {\n    int fd = socket(AF_INET, SOCK_STREAM, 0);\n    if (fd < 0) return -1;\n    return fd;\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 30, "end_line": 35,
        },
    ]:
        db.save_function(fid1, fn)

    # File 2: http.cpp
    fid2 = db.save_file(aid, f"{BASE}/src/network/http.cpp")
    for fn in [
        {
            "name": "parse_content_length",
            "code": 'int parse_content_length(const char* header) {\n    int len;\n    sscanf(header, "Content-Length: %d", &len);\n    char* body = (char*)malloc(len * 4);\n    return len;\n}',
            "verdict": "vulnerable", "cwe": "CWE-190", "cwe_name": "Integer Overflow",
            "severity": "High", "confidence": None, "start_line": 5, "end_line": 11,
        },
        {
            "name": "send_response",
            "code": 'void send_response(int sock, const char* body) {\n    char buf[256];\n    sprintf(buf, "HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\n\\r\\n%s",\n            strlen(body), body);\n    send(sock, buf, strlen(buf), 0);\n}',
            "verdict": "vulnerable", "cwe": "CWE-787", "cwe_name": "Out-of-bounds Write",
            "severity": "Critical", "confidence": None, "start_line": 14, "end_line": 21,
        },
        {
            "name": "build_get_request",
            "code": 'std::string build_get_request(const std::string& path) {\n    return "GET " + path + " HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n";\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 24, "end_line": 27,
        },
        {
            "name": "url_decode",
            "code": 'std::string url_decode(const std::string& in) {\n    std::string out;\n    for (size_t i = 0; i < in.size(); ++i) {\n        if (in[i] == \'%\' && i+2 < in.size()) {\n            out += (char)strtol(in.substr(i+1,2).c_str(), nullptr, 16);\n            i += 2;\n        } else out += in[i];\n    }\n    return out;\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 30, "end_line": 41,
        },
    ]:
        db.save_function(fid2, fn)

    # File 3: string_utils.cpp
    fid3 = db.save_file(aid, f"{BASE}/src/utils/string_utils.cpp")
    for fn in [
        {
            "name": "str_concat",
            "code": 'char* str_concat(const char* a, const char* b) {\n    char buf[128];\n    strcpy(buf, a);\n    strcat(buf, b);\n    return buf;\n}',
            "verdict": "vulnerable", "cwe": "CWE-787", "cwe_name": "Out-of-bounds Write",
            "severity": "Critical", "confidence": None, "start_line": 4, "end_line": 10,
        },
        {
            "name": "str_split_index",
            "code": 'char get_char_at(const char* str, int idx) {\n    return str[idx];\n}',
            "verdict": "vulnerable", "cwe": "CWE-125", "cwe_name": "Out-of-bounds Read",
            "severity": "High", "confidence": None, "start_line": 13, "end_line": 15,
        },
        {
            "name": "str_to_int",
            "code": 'int str_to_int(const char* s) {\n    if (!s) return 0;\n    return atoi(s);\n}',
            "verdict": "vulnerable", "cwe": "CWE-476", "cwe_name": "NULL Pointer Dereference",
            "severity": "Medium", "confidence": None, "start_line": 18, "end_line": 22,
        },
        {
            "name": "str_length",
            "code": 'size_t str_length(const std::string& s) {\n    return s.size();\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 25, "end_line": 27,
        },
        {
            "name": "str_to_upper",
            "code": 'std::string str_to_upper(std::string s) {\n    for (auto& c : s) c = toupper(c);\n    return s;\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 30, "end_line": 34,
        },
    ]:
        db.save_function(fid3, fn)

    # File 4: memory.cpp
    fid4 = db.save_file(aid, f"{BASE}/src/utils/memory.cpp")
    for fn in [
        {
            "name": "safe_free",
            "code": 'void safe_free(void** ptr) {\n    if (ptr && *ptr) {\n        free(*ptr);\n        *ptr = nullptr;\n    }\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 3, "end_line": 9,
        },
        {
            "name": "pool_alloc",
            "code": 'void* pool_alloc(MemPool* pool, size_t sz) {\n    if (!pool) return nullptr;\n    if (pool->used + sz > pool->cap) return nullptr;\n    void* p = pool->buf + pool->used;\n    pool->used += sz;\n    return p;\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 12, "end_line": 19,
        },
        {
            "name": "release_buffer",
            "code": 'void release_buffer(char* buf) {\n    free(buf);\n    free(buf);\n}',
            "verdict": "vulnerable", "cwe": "CWE-415", "cwe_name": "Double Free",
            "severity": "High", "confidence": None, "start_line": 22, "end_line": 25,
        },
        {
            "name": "compute_ratio",
            "code": 'float compute_ratio(int total, int part) {\n    return (float)part / total;\n}',
            "verdict": "vulnerable", "cwe": "CWE-369", "cwe_name": "Divide By Zero",
            "severity": "Medium", "confidence": None, "start_line": 28, "end_line": 30,
        },
    ]:
        db.save_function(fid4, fn)

    # File 5: parser.cpp
    fid5 = db.save_file(aid, f"{BASE}/src/core/parser.cpp")
    for fn in [
        {
            "name": "parse_int_field",
            "code": 'int parse_int_field(const char* data, int offset, int count) {\n    int result = 0;\n    for (int i = 0; i < count; i++)\n        result = result * 256 + (unsigned char)data[offset + i];\n    return result;\n}',
            "verdict": "vulnerable", "cwe": "CWE-125", "cwe_name": "Out-of-bounds Read",
            "severity": "High", "confidence": None, "start_line": 6, "end_line": 13,
        },
        {
            "name": "parse_packet_size",
            "code": 'uint32_t parse_packet_size(uint16_t a, uint16_t b) {\n    return a * b;\n}',
            "verdict": "vulnerable", "cwe": "CWE-190", "cwe_name": "Integer Overflow",
            "severity": "High", "confidence": None, "start_line": 16, "end_line": 19,
        },
        {
            "name": "validate_checksum",
            "code": 'bool validate_checksum(const uint8_t* data, size_t len, uint16_t expected) {\n    uint16_t sum = 0;\n    for (size_t i = 0; i < len; i++) sum += data[i];\n    return sum == expected;\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 22, "end_line": 27,
        },
        {
            "name": "read_null_terminated",
            "code": 'std::string read_null_terminated(const char* src) {\n    if (!src) return "";\n    return std::string(src);\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 30, "end_line": 34,
        },
        {
            "name": "parse_version",
            "code": 'void parse_version(const char* hdr, int* major, int* minor) {\n    sscanf(hdr, "Version: %d.%d", major, minor);\n}',
            "verdict": "safe", "cwe": None, "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 37, "end_line": 40,
        },
    ]:
        db.save_function(fid5, fn)

    total = 4 + 4 + 5 + 4 + 5
    vuln = 11  # as counted in original script
    print(f"✓ Seeded multi‑file analysis — ID {aid}")
    print(f"  Project : {PROJECT} ({BASE})")
    print(f"  Files   : 5 (socket, http, string_utils, memory, parser)")
    print(f"  Functions: {total}  |  Vulnerable: {vuln}  |  Safe: {total - vuln}")
    print(f"  Navigate to: /report/{aid}\n")

def seed_multi_cwe():
    """Original reports_generator.py: functions with multiple CWEs per function."""
    PROJECT = "multi_cwe_test"
    BASE = "C:/Users/test/Desktop/multi_cwe_test"

    aid = db.save_analysis(PROJECT, BASE)

    # File 1: vulnerable_socket.cpp
    fid1 = db.save_file(aid, f"{BASE}/src/vulnerable_socket.cpp")
    for fn in [
        {
            "name": "recv_data",
            "code": 'int recv_data(int sock, char* buf, int len) {\n    char tmp[64];\n    int n = recv(sock, tmp, len, 0);\n    memcpy(buf, tmp, n);\n    return n;\n}',
            "verdict": "vulnerable",
            "cwe": json.dumps(["CWE-787", "CWE-125"]),
            "cwe_name": "Out-of-bounds Write + Read",
            "severity": "Critical", "confidence": 0.92, "start_line": 8, "end_line": 14,
        },
        {
            "name": "parse_header",
            "code": 'void parse_header(char* raw, Header* out) {\n    char key[32];\n    sscanf(raw, "%s: %s", key, out->value);\n}',
            "verdict": "vulnerable",
            "cwe": json.dumps(["CWE-190", "CWE-476"]),
            "cwe_name": "Integer Overflow + NULL Pointer",
            "severity": "High", "confidence": 0.85, "start_line": 17, "end_line": 21,
        },
        {
            "name": "close_socket",
            "code": 'void close_socket(int sock) {\n    if (sock >= 0)\n        close(sock);\n}',
            "verdict": "safe", "cwe": json.dumps([]), "cwe_name": None,
            "severity": None, "confidence": None, "start_line": 24, "end_line": 27,
        },
    ]:
        db.save_function(fid1, fn)

    # File 2: http_parser.cpp
    fid2 = db.save_file(aid, f"{BASE}/src/http_parser.cpp")
    for fn in [
        {
            "name": "parse_content_length",
            "code": 'int parse_content_length(const char* header) {\n    int len;\n    sscanf(header, "Content-Length: %d", &len);\n    char* body = (char*)malloc(len * 4);\n    return len;\n}',
            "verdict": "vulnerable",
            "cwe": json.dumps(["CWE-190", "CWE-787"]),
            "cwe_name": "Integer Overflow + Out-of-bounds Write",
            "severity": "Critical", "confidence": 0.88, "start_line": 5, "end_line": 11,
        },
        {
            "name": "send_response",
            "code": 'void send_response(int sock, const char* body) {\n    char buf[256];\n    sprintf(buf, "HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\n\\r\\n%s",\n            strlen(body), body);\n    send(sock, buf, strlen(buf), 0);\n}',
            "verdict": "vulnerable",
            "cwe": json.dumps(["CWE-787"]),
            "cwe_name": "Out-of-bounds Write",
            "severity": "Critical", "confidence": 0.95, "start_line": 14, "end_line": 21,
        },
    ]:
        db.save_function(fid2, fn)

    # (Optional: add 3 more files as per comment – left as in original)

    print(f"✓ Seeded multi‑CWE analysis — ID {aid}")
    print(f"  Project : {PROJECT}")
    print(f"  Files   : 2+ (with functions having multiple CWEs)")
    print(f"  Navigate to: /report/{aid}\n")

if __name__ == "__main__":
    db.init_db()
    seed_single_file()
    seed_multi_file()
    seed_multi_cwe()
    print("All seeding completed.")