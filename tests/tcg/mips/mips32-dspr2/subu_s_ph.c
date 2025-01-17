#include <stdio.h>
#include <assert.h>

int main()
{
    int rd, rs, rt, dsp;
    int result, resultdsp;

    rs = 0x87654321;
    rt = 0x12345678;
    result    = 0x75310000;
    resultdsp = 0x01;

    __asm
        ("subu_s.ph %0, %2, %3\n\t"
         "rddsp %1\n\t"
         : "=r"(rd), "=r"(dsp)
         : "r"(rs), "r"(rt)
        );
    dsp = (dsp >> 20) & 0x01;
    assert(dsp == resultdsp);
    assert(rd  == result);

    return 0;
}
