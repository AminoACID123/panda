#include <stdio.h>
#include <assert.h>

int main()
{
    int rt, rs;
    int achi, acli;
    int dsp;
    int acho, aclo;
    int resulth, resultl;
    int resdsp;

    achi = 0x00000005;
    acli = 0x0000B4CB;
    rs  = 0x0000FF06;
    rt  = 0x0000CB00;
    resulth = 0x00000005;
    resultl = 0x006838CB;

    __asm
        ("mthi %2, $ac1\n\t"
         "mtlo %3, $ac1\n\t"
         "maq_s.w.phr $ac1, %4, %5\n\t"
         "mfhi %0, $ac1\n\t"
         "mflo %1, $ac1\n\t"
         : "=r"(acho), "=r"(aclo)
         : "r"(achi), "r"(acli), "r"(rs), "r"(rt)
        );
    assert(resulth == acho);
    assert(resultl == aclo);

    achi = 0x00000006;
    acli = 0x0000B4CB;
    rs  = 0x00008000;
    rt  = 0x00008000;
    resulth = 0x00000006;
    resultl = 0x8000B4CA;
    resdsp = 1;

    __asm
        ("mthi %3, $ac1\n\t"
         "mtlo %4, $ac1\n\t"
         "maq_s.w.phr $ac1, %5, %6\n\t"
         "mfhi %0, $ac1\n\t"
         "mflo %1, $ac1\n\t"
         "rddsp %2\n\t"
         : "=r"(acho), "=r"(aclo), "=r"(dsp)
         : "r"(achi), "r"(acli), "r"(rs), "r"(rt)
        );
    assert(resulth == acho);
    assert(resultl == aclo);
    assert(((dsp >> 17) & 0x01) == resdsp);

    return 0;
}
