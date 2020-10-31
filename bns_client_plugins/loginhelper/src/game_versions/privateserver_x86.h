#include <cinttypes>

#include <span>

namespace ps_x86
{
    bool hook(std::span<char> data, const wchar_t* username, const wchar_t* password, const wchar_t* pin);
}
