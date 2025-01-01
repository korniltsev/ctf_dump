#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"
#include "stdint.h"

typedef struct
{
  uint64 regs[30];
  uint64 rsp;
  uint64 rip;
  uint64 code_start;
  uint64 code_end;

} vm;

#define __fastcall
#define _byteswap_ulong __builtin_bswap32
#define _byteswap_uint64 __builtin_bswap64

uint64 __ROL8__(uint64 a, uint64 b)
{
  return a;//todo
}
uint64 __ROR8__(uint64 a, uint64 b)
{
  return a;//todo
}
__int64 __fastcall vm_step(vm *a1)
{
  __int64 rax; // rax
  unsigned int *rip; // rdx
  unsigned int v4; // edi
  __int64 v5; // r14
  __int64 opcode; // rdi
  unsigned int typ; // r8d
  __int64 dst_regno; // rsi
  __int64 rv; // rcx
  __int64 lvv; // rdx
  unsigned int cmpTyp; // edi
  uint64_t v12; // rcx
  __int64 *v13; // rax
  __int64 regno; // rdi
  __int64 (__fastcall *v15)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, __int64); // r10
  __int64 rsp; // rax
  char shl; // cl
  uint64_t v18; // rdx
  unsigned int v19; // edx
  unsigned int v20; // ecx
  unsigned __int64 *v21; // rax
  unsigned __int64 v22; // rcx
  __int64 v23; // [rsp-8h] [rbp-18h]

  v23 = rax;
  rip = (unsigned int *)a1->rip;
  v4 = *rip;
  v5 = (__int64)(rip + 1);
  a1->rip = (__int64)(rip + 1);
  opcode = _byteswap_ulong(v4);
  typ = (unsigned int)opcode >> 29;
  if ( (unsigned int)opcode < 0x20000000 || typ == 1 && (rax = opcode & 0x10000000, (opcode & 0x10000000) == 0) )
  {
    dst_regno = ((unsigned int)opcode >> 19) & 0x1F;
    if ( (BYTE3(opcode) & 1 & (typ == 1)) != 0 || (opcode & 0xE1000000) == 0 )
    {
      if ( typ == 1 || (unsigned int)opcode >> 25 == 9 || (unsigned int)opcode >> 25 == 7 )
        rv = opcode << 50 >> 50;
      else
        rv = opcode & 0x3FFF;
    }
    else
    {
      rv = a1->regs[((unsigned int)opcode >> 9) & 0x1F];
    }
    lvv = a1->regs[((unsigned int)opcode >> 14) & 0x1F];
    cmpTyp = (unsigned int)opcode >> 25;
    if ( typ == 1 )
    {
      switch ( cmpTyp & 7 )
      {
        case 0u:
          rax = lvv == rv;
          a1->regs[dst_regno] = rax;
          break;
        case 1u:
          rax = lvv != rv;
          a1->regs[dst_regno] = rax;
          break;
        case 2u:
          rax = lvv <= rv;
          a1->regs[dst_regno] = rax;
          break;
        case 3u:
          rax = lvv < rv;
          a1->regs[dst_regno] = rax;
          break;
        case 4u:
          rax = lvv <= (unsigned __int64)rv;
          a1->regs[dst_regno] = rax;
          break;
        case 5u:
          rax = lvv < (unsigned __int64)rv;
          a1->regs[dst_regno] = rax;
          break;
        default:
LABEL_20:
          rax = 0LL;
          a1->regs[dst_regno] = 0LL;
          break;
      }
    }
    else
    {
      switch ( cmpTyp & 0xF )
      {
        case 0u:
          v12 = lvv | rv;
          goto LABEL_38;
        case 1u:
          v12 = lvv ^ rv;
          goto LABEL_38;
        case 2u:
          v12 = lvv & rv;
          goto LABEL_38;
        case 3u:
          v12 = lvv + rv;
          goto LABEL_38;
        case 4u:
          v18 = lvv - rv;
          goto LABEL_48;
        case 5u:
          v12 = lvv * rv;
LABEL_38:
          rax = v12;
          a1->regs[dst_regno] = v12;
          return rax;
        case 6u:
          rax = lvv / (unsigned __int64)rv;
          a1->regs[dst_regno] = lvv / (unsigned __int64)rv;
          return rax;
        case 7u:
          rax = lvv / rv;
          a1->regs[dst_regno] = lvv / rv;
          return rax;
        case 8u:
          v18 = lvv % (unsigned __int64)rv;
          goto LABEL_48;
        case 9u:
          v18 = lvv % rv;
          goto LABEL_48;
        case 0xAu:
          v18 = lvv << rv;
          goto LABEL_48;
        case 0xBu:
          v18 = lvv >> rv;
          goto LABEL_48;
        case 0xCu:
          v18 = (unsigned __int64)lvv >> rv;
          goto LABEL_48;
        case 0xDu:
          v18 = __ROL8__(lvv, rv);
          goto LABEL_48;
        case 0xEu:
          v18 = __ROR8__(lvv, rv);
LABEL_48:
          rax = v18;
          a1->regs[dst_regno] = v18;
          break;
        default:
          goto LABEL_20;
      }
    }
    return rax;
  }
  if ( typ == 1 )
  {
    typ = ((unsigned int)opcode >> 26) & 3;
    if ( typ == 2 )
    {
      regno = ((unsigned int)opcode >> 20) & 0x1F;
      v15 = (__int64 (__fastcall *)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, __int64))a1->regs[regno];
      if ( (unsigned __int64)v15 < a1->code_start || (unsigned __int64)v15 >= a1->code_end )
      {
        rax = v15(a1->regs[0], a1->regs[1], a1->regs[2], a1->regs[3], a1->regs[4], a1->regs[5], v23);
        a1->regs[0] = rax;
        a1->rip = v5;
      }
      else
      {
        rsp = a1->rsp;
        *(_QWORD *)(rsp - 8) = v5;
        rax = rsp - 8;
        a1->rip = a1->regs[regno];
        a1->rsp = rax;
      }
      return rax;
    }
    if ( !typ )
    {
      v13 = (__int64 *)a1->rsp;
      a1->rip = *v13;
      rax = (__int64)(v13 + 1);
      a1->rsp = rax;
      return rax;
    }
    if ( (opcode & 0x2000000) != 0 )
    {
      rax = 37LL;
      shl = 39;
    }
    else
    {
      rax = ((unsigned int)opcode >> 20) & 0x1F;
      if ( !a1->regs[rax] )
        goto LABEL_52;
      rax = 42LL;
      shl = 44;
    }
    a1->rip = (__int64)rip + ((__int64)((unsigned __int64)(unsigned int)opcode << shl) >> rax);
LABEL_52:
    if ( (opcode & 0x2000000) == 0 )
      return rax;
  }
  if ( typ == 2 )
  {
    if ( (((unsigned int)opcode >> 27) & 3) != 0 )
    {
      v19 = ((unsigned int)opcode >> 21) & 0x1F;
      v20 = WORD1(opcode) & 0x1F;
      rax = (unsigned __int16)opcode - 0x8000LL;
      if ( (opcode & 0x8000u) == 0LL )
        rax = (unsigned __int16)opcode;
      if ( (((unsigned int)opcode >> 27) & 3) == 1 )
      {
        rax = *(_QWORD *)(a1->regs[v20] + rax);
        a1->regs[v19] = rax;
      }
      else
      {
        switch ( ((unsigned int)opcode >> 26) & 3 )
        {
          case 0u:
            *(_BYTE *)(a1->regs[v20] + rax) = a1->regs[v19];
            break;
          case 1u:
            *(_WORD *)(a1->regs[v20] + rax) = a1->regs[v19];
            break;
          case 2u:
            *(_DWORD *)(a1->regs[v20] + rax) = a1->regs[v19];
            break;
          case 3u:
            *(_QWORD *)(a1->regs[v20] + rax) = a1->regs[v19];
            break;
        }
      }
    }
    else
    {
      v21 = (unsigned __int64 *)a1->rip;
      v22 = _byteswap_uint64(*v21);
      rax = (__int64)(v21 + 1);
      a1->rip = rax;
      a1->regs[WORD1(opcode) & 0x1F] = v22;
    }
  }
  return rax;
}

vm v =  {};

void check(uint8_t *code, int sz)
{
  v.rip = code;
  v.code_start = code;
  v.code_end = code + sz;
  vm_step(&v);
}

void checku32(uint32 a)
{
  check(&a, sizeof(a));
}

void hexcheck(char *s)
{
  uint8 *raw = malloc(strlen(s));
  memset(raw, 0, strlen(s));
  uint8 *it = raw;
  int cnt = 0;
  while (1)
  {
    int b = 0;
    int n = sscanf(s, "%x", &b);
    if (n != 1) {
      break;
    }
    cnt++;
    *it = b;
    it++;
    s+= 2;
    if (*s == ' ') {
      s +=1;
    }


  }
  check(raw, cnt);

}

int main(void)
{
//   00000000  08 f7 80 10 06 17 80 08  40 03 00 00 00 00 00 00  |........@.......|
// 00000010  3f 6f 62 76 5c 62 00 00  40 03 00 00 00 00 00 00  |?obv\b..@.......|
// 00000020  ff ff ff ff 05 08 46 00  23 08 40 12 34 10 00 e7  |......F.#.@.4...|
// 00000030  48 60 00 07 40 01 00 00  00 00 00 00 ff 00 00 00  |H`..@...........|
// 00000040  48 9e 00 08 05 21 02 00  18 21 00 18 04 18 c0 ff  |H....!...!......|
// 00000050  02 18 c0 0c 22 19 06 00  34 30 00 dc 40 03 00 00  |...."...40..@...|
// 00000060  00 00 00 00 59 63 1b 35  48 9e 00 08 0b 29 06 00  |....Yc.5H....)..|
// 00000070  40 04 00 00 00 00 00 00  b4 b1 a6 69 07 29 48 00  |@..........i.)H.|
// 00000080  5c a2 00 00 48 a0 00 08  48 de 00 08 05 31 82 00  |\...H...H....1..|
// 00000090  18 31 80 18 04 29 40 ff  02 29 40 47 22 29 8a 00  |.1...)@..)@G")..|
    hexcheck("5c 62 00 00");

    return 0;
}