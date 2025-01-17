#include <stdio.h>
#include <assert.h>

int main()
{
    int rd, rs, rt;
    int result;

    rs     = 0x00000010;
    rt     = 0x00000001;
    result = 0x00000009;

    __asm
        ("addqh_r.w  %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );

    assert(rd == result);

    rs     = 0xFFFFFFFE;
    rt     = 0x00000001;
    result = 0x00000000;

    __asm
        ("addqh_r.w  %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );

    assert(rd == result);

    return 0;
}
