#include <vector>
#include <plugindbg.h>
#include <cinttypes>
#include "pattern.h"

#define CONCAT2(x, y) x ## y
#define CONCAT(x, y) CONCAT2(x, y)

#define DEFINE_PATTERN(name) \
    static std::vector<char_pat> name; \
    static int32_t CONCAT(name, _offset);

#define INIT_PATTERN_INTERNAL(a, b, offset, pat) \
    static auto b = xorstr(pat); \
    b.crypt(); \
    a = load_pattern(b.get()); \
    CONCAT(a, _offset) = (offset);
#define INIT_PATTERN(a, offset, pat) INIT_PATTERN_INTERNAL(a, CONCAT(_tmp,__COUNTER__), offset, pat)

#define FIND_OR_RETURN_INTERNAL(var, pattern, tmp) \
    const int32_t tmp = pattern_scan(data, pattern); \
    if (tmp == -1) { dbg_printf("Failed to find: %s\n", #pattern); return false;}; \
    uintptr_t var = (uintptr_t)data.data() + tmp + CONCAT(pattern, _offset); \
    dbg_printf("Found %s at: %X\n", #pattern, var);
#define FIND_OR_RETURN(var, pattern) FIND_OR_RETURN_INTERNAL(var, pattern, CONCAT(qtmp__, __COUNTER__))
