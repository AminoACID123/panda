#include <stdio.h>
#include <assert.h>

int main()
{
    int rd, rs, rt, dsp;
    int result, resultdsp;

    rs = 0x8000;
    rt = 0x80004321;
    result = 0xFFFF0000;
    resultdsp = 1;

    __asm
        ("muleu_s.ph.qbr %0, %2, %3\n\t"
         "rddsp %1\n\t"
         : "=r"(rd), "=r"(dsp)
         : "r"(rs), "r"(rt)
        );
    dsp = (dsp >> 21) & 0x01;
    assert(rd  == result);
    assert(dsp == resultdsp);

    return 0;
}
