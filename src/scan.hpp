#pragma once

namespace scanner
{
    // Takes IDA Style Signatures and searches a module for matching bytes, returns first occurence
    void *scan(std::string_view signature, std::string_view name, HMODULE mod);
    std::vector<void*> scan_multi(std::string_view signature, HMODULE mod);
    void *rip(void *address, uintptr_t offset = 1);
}