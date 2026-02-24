"""
Multi-file project seed for UI testing.
Usage: cd backend && python seed_multi.py
"""
from database import db

db.init_db()

PROJECT = "network_utils"
BASE    = "C:/Users/test/Desktop/network_utils"

aid = db.save_analysis(PROJECT, BASE)

# ── File 1: socket.cpp ───────────────────────────────
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

# ── File 2: http.cpp ─────────────────────────────────
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

# ── File 3: string_utils.cpp ─────────────────────────
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

# ── File 4: memory.cpp ───────────────────────────────
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

# ── File 5: parser.cpp ───────────────────────────────
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
vuln  = sum(1 for f in [
    *[None]*2, *[None]*0,  # socket: 2 vuln
    *[None]*2, *[None]*0,  # http: 2 vuln
    *[None]*3, *[None]*0,  # string: 3 vuln
    *[None]*2, *[None]*0,  # memory: 2 vuln
    *[None]*2, *[None]*0,  # parser: 2 vuln
] if f is None) 

print(f"✓ Seeded multi-file analysis — ID {aid}")
print(f"  Project : {PROJECT} ({BASE})")
print(f"  Files   : 5  (socket, http, string_utils, memory, parser)")
print(f"  Functions: {total}  |  Vulnerable: 11  |  Clean: {total - 11}")
print(f"  Navigate to: /report/{aid}")