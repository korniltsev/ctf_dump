#include <assert.h>

#include "mydefs.h"
#include "stdio.h"

int main()
{


    uint64 b = 0xcafebabedeadbeef;
    uint64 b1 = __builtin_bswap64(b);
    uint64 b2 = __ROL8__(b, 8);
    uint64 b3 = __ROR8__(b, 8);
    assert(b1 == 0xefbeaddebebafeca);
    assert(b2 == 0xfebabedeadbeefca);
    assert(b3 == 0xefcafebabedeadbe);


    return 0;
}
