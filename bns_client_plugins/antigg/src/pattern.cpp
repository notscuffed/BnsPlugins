#include "pattern.h"

std::vector<char_pat> load_pattern(const char* pattern)
{
    std::vector<char_pat> out{};
    char_pat current;

    const char* patternEnd = pattern + strlen(pattern);

    for (const char* i = pattern; i < patternEnd; i++)
    {
        if (*i == '?') {
            while (*i == '?') i++;
            current.c = '?';
            current.w = '?';
            out.push_back(current);
            continue;
        }

        current.c = (char)strtol(i, (char**) &i, 16);
        current.w = '#';
        out.push_back(current);
    }

    return std::move(out);
}
