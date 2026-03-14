#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cctype>

#include <aes.hpp>

extern uint8_t epkKeys[][16];
extern size_t epkKeyCount;

void decryptAES128ecbUnalign(uint8_t* data, size_t len, const uint8_t key[16]);
const uint8_t* tryFindAESkey(const uint8_t* data, size_t len, const uint8_t* magic, size_t magic_len, size_t offset);