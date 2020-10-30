#pragma once
#include <vector>
#include <span>

struct char_pat {
    char c;
    char w;
};

std::vector<char_pat> load_pattern(const char* pattern);

template <class T>
int32_t pattern_scan(std::span<T> memory, std::vector<char_pat>& pattern) {
    int patternLength = pattern.size();
    const char_pat* patternBegin = &pattern[0];
    const char_pat* patternEnd = patternBegin + patternLength;

    for (const T* i = memory.data(); i + patternLength < memory.data() + memory.size(); i++) {
        const T* ci = i;

        for (const char_pat* j = patternBegin; j < patternEnd; j++) {
            if ((T)j->c != *ci && j->w != '?')
                goto SKIP;
            ci++;
        }

        return (int32_t)(i - memory.data());
    SKIP:;
    }

    return -1;
}
