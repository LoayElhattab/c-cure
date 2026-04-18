#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>

// CLEAN: safely compute length of a null-terminated string with upper bound
size_t safe_strlen(const char* s, size_t max_len) {
    if (!s) return 0;
    size_t i = 0;
    while (i < max_len && s[i]) i++;
    return i;
}

// CLEAN: safe copy with guaranteed null termination
void safe_strcpy(char* dst, const char* src, size_t dst_size) {
    if (!dst || !src || dst_size == 0) return;
    size_t i = 0;
    while (i < dst_size - 1 && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

// BUG (CWE-125): searches for pattern in text using text_len as bound
// but accesses text[i + j] where j goes up to pattern_len — can read past text+text_len
int find_pattern(const char* text, size_t text_len, const char* pattern, size_t pattern_len) {
    for (size_t i = 0; i <= text_len - pattern_len; i++) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; j++) {
            if (text[i + j] != pattern[j]) {  // CWE-125: i+j may exceed text_len
                match = false;
                break;
            }
        }
        if (match) return (int)i;
    }
    return -1;
}

// BUG (CWE-787): joins strings into a fixed-size buffer of out_size bytes
// does not check total length before writing — can overflow out
void str_join(const char** parts, int count, char sep, char* out, size_t out_size) {
    size_t pos = 0;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(parts[i]);
        memcpy(out + pos, parts[i], len);  // CWE-787: no check that pos+len < out_size
        pos += len;
        if (i < count - 1) out[pos++] = sep;
    }
    out[pos] = '\0';
}

// CLEAN: trim leading and trailing whitespace in-place
void str_trim(char* s) {
    if (!s || !*s) return;
    // trim leading
    int start = 0;
    while (s[start] && isspace((unsigned char)s[start])) start++;
    memmove(s, s + start, strlen(s) - start + 1);
    // trim trailing
    int end = (int)strlen(s) - 1;
    while (end >= 0 && isspace((unsigned char)s[end])) s[end--] = '\0';
}

// CLEAN: convert string to integer with error detection
int str_to_int_safe(const char* s, int* out, int default_val) {
    if (!s || !out) return -1;
    char* end;
    long val = strtol(s, &end, 10);
    if (end == s || *end != '\0') {
        *out = default_val;
        return -1;
    }
    *out = (int)val;
    return 0;
}
