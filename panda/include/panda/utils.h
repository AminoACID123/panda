#pragma once

#define SWAP16(_x)                          \
  ({                                        \
                                            \
    uint16_t _ret = (_x);                   \
    (uint16_t)((_ret << 8) | (_ret >> 8));  \
                                            \
  })

#define SWAP32(_x)                                                          \
  ({                                                                        \
                                                                            \
    uint32_t _ret = (_x);                                                   \
    (uint32_t)((_ret << 24) | (_ret >> 24) | ((_ret << 8) & 0x00FF0000) |   \
          ((_ret >> 8) & 0x0000FF00));                                      \
                                                                            \
  })

#define SWAP64(_x)                                                             \
  ({                                                                           \
                                                                               \
    uint64_t _ret = (_x);                                                      \
    _ret =                                                                     \
        (_ret & 0x00000000FFFFFFFF) << 32 | (_ret & 0xFFFFFFFF00000000) >> 32; \
    _ret =                                                                     \
        (_ret & 0x0000FFFF0000FFFF) << 16 | (_ret & 0xFFFF0000FFFF0000) >> 16; \
    _ret =                                                                     \
        (_ret & 0x00FF00FF00FF00FF) << 8 | (_ret & 0xFF00FF00FF00FF00) >> 8;   \
    _ret;                                                                      \
                                                                               \
  })

