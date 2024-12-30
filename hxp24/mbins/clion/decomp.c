#include "defs.h"
#include "mydefs.h"

__int64 __fastcall sub_13B0(__int64 *a1)
{
  __int64 result; // rax
  unsigned int *v3; // rdx
  unsigned int v4; // edi
  unsigned int *v5; // r14
  __int64 v6; // rdi
  unsigned int v7; // r8d
  __int64 v8; // rsi
  __int64 v9; // rcx
  __int64 v10; // rdx
  unsigned int v11; // edi
  __int64 v12; // rcx
  __int64 *v13; // rax
  __int64 v14; // rdi
  __int64 (__fastcall *v15)(__int64, __int64, __int64, __int64, __int64, __int64, __int64); // r10
  __int64 v16; // rax
  char v17; // cl
  __int64 v18; // rdx
  unsigned int v19; // edx
  unsigned int v20; // ecx
  unsigned __int64 *v21; // rax
  unsigned __int64 v22; // rcx
  __int64 v23; // [rsp-8h] [rbp-18h]

  v23 = result;
  v3 = (unsigned int *)a1[31];
  v4 = *v3;
  v5 = v3 + 1;
  a1[31] = (__int64)(v3 + 1);
  v6 = _byteswap_ulong(v4);
  v7 = (unsigned int)v6 >> 29;
  if ( (unsigned int)v6 < 0x20000000 || v7 == 1 && (result = v6 & 0x10000000, (v6 & 0x10000000) == 0) )
  {
    v8 = ((unsigned int)v6 >> 19) & 0x1F;
    if ( (BYTE3(v6) & 1 & (v7 == 1)) != 0 || (v6 & 0xE1000000) == 0 )
    {
      if ( v7 == 1 || (unsigned int)v6 >> 25 == 9 || (unsigned int)v6 >> 25 == 7 )
        v9 = v6 << 50 >> 50;
      else
        v9 = v6 & 0x3FFF;
    }
    else
    {
      v9 = a1[((unsigned int)v6 >> 9) & 0x1F];
    }
    v10 = a1[((unsigned int)v6 >> 14) & 0x1F];
    v11 = (unsigned int)v6 >> 25;
    if ( v7 == 1 )
    {
      switch ( v11 & 7 )
      {
        case 0u:
          result = v10 == v9;
          a1[v8] = result;
          break;
        case 1u:
          result = v10 != v9;
          a1[v8] = result;
          break;
        case 2u:
          result = v10 <= v9;
          a1[v8] = result;
          break;
        case 3u:
          result = v10 < v9;
          a1[v8] = result;
          break;
        case 4u:
          result = v10 <= (unsigned __int64)v9;
          a1[v8] = result;
          break;
        case 5u:
          result = v10 < (unsigned __int64)v9;
          a1[v8] = result;
          break;
        default:
LABEL_20:
          result = 0LL;
          a1[v8] = 0LL;
          break;
      }
    }
    else
    {
      switch ( v11 & 0xF )
      {
        case 0u:
          v12 = v10 | v9;
          goto LABEL_38;
        case 1u:
          v12 = v10 ^ v9;
          goto LABEL_38;
        case 2u:
          v12 = v10 & v9;
          goto LABEL_38;
        case 3u:
          v12 = v10 + v9;
          goto LABEL_38;
        case 4u:
          v18 = v10 - v9;
          goto LABEL_48;
        case 5u:
          v12 = v10 * v9;
LABEL_38:
          result = v12;
          a1[v8] = v12;
          return result;
        case 6u:
          result = v10 / (unsigned __int64)v9;
          a1[v8] = v10 / (unsigned __int64)v9;
          return result;
        case 7u:
          result = v10 / v9;
          a1[v8] = v10 / v9;
          return result;
        case 8u:
          v18 = v10 % (unsigned __int64)v9;
          goto LABEL_48;
        case 9u:
          v18 = v10 % v9;
          goto LABEL_48;
        case 0xAu:
          v18 = v10 << v9;
          goto LABEL_48;
        case 0xBu:
          v18 = v10 >> v9;
          goto LABEL_48;
        case 0xCu:
          v18 = (unsigned __int64)v10 >> v9;
          goto LABEL_48;
        case 0xDu:
          v18 = __ROL8__(v10, v9);
          goto LABEL_48;
        case 0xEu:
          v18 = __ROR8__(v10, v9);
LABEL_48:
          result = v18;
          a1[v8] = v18;
          break;
        default:
          goto LABEL_20;
      }
    }
    return result;
  }
  if ( v7 == 1 )
  {
    v7 = ((unsigned int)v6 >> 26) & 3;
    if ( v7 == 2 )
    {
      v14 = ((unsigned int)v6 >> 20) & 0x1F;
      v15 = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64, __int64))a1[v14];
      if ( (unsigned __int64)v15 < a1[32] || (unsigned __int64)v15 >= a1[33] )
      {
        result = v15(*a1, a1[1], a1[2], a1[3], a1[4], a1[5], v23);
        *a1 = result;
        a1[31] = (__int64)v5;
      }
      else
      {
        v16 = a1[30];
        *(_QWORD *)(v16 - 8) = v5;
        result = v16 - 8;
        a1[31] = a1[v14];
        a1[30] = result;
      }
      return result;
    }
    if ( !v7 )
    {
      v13 = (__int64 *)a1[30];
      a1[31] = *v13;
      result = (__int64)(v13 + 1);
      a1[30] = result;
      return result;
    }
    if ( (v6 & 0x2000000) != 0 )
    {
      result = 37LL;
      v17 = 39;
    }
    else
    {
      result = ((unsigned int)v6 >> 20) & 0x1F;
      if ( !a1[result] )
        goto LABEL_52;
      result = 42LL;
      v17 = 44;
    }
    a1[31] = (__int64)v3 + ((__int64)((unsigned __int64)(unsigned int)v6 << v17) >> result);
LABEL_52:
    if ( (v6 & 0x2000000) == 0 )
      return result;
  }
  if ( v7 == 2 )
  {
    if ( (((unsigned int)v6 >> 27) & 3) != 0 )
    {
      v19 = ((unsigned int)v6 >> 21) & 0x1F;
      v20 = WORD1(v6) & 0x1F;
      result = (unsigned __int16)v6 - 0x8000LL;
      if ( (v6 & 0x8000u) == 0LL )
        result = (unsigned __int16)v6;
      if ( (((unsigned int)v6 >> 27) & 3) == 1 )
      {
        result = *(_QWORD *)(a1[v20] + result);
        a1[v19] = result;
      }
      else
      {
        switch ( ((unsigned int)v6 >> 26) & 3 )
        {
          case 0u:
            *(_BYTE *)(a1[v20] + result) = a1[v19];
            break;
          case 1u:
            *(_WORD *)(a1[v20] + result) = a1[v19];
            break;
          case 2u:
            *(_DWORD *)(a1[v20] + result) = a1[v19];
            break;
          case 3u:
            *(_QWORD *)(a1[v20] + result) = a1[v19];
            break;
        }
      }
    }
    else
    {
      v21 = (unsigned __int64 *)a1[31];
      v22 = _byteswap_uint64(*v21);
      result = (__int64)(v21 + 1);
      a1[31] = result;
      a1[WORD1(v6) & 0x1F] = v22;
    }
  }
  return result;
}

int main()
{
  return 0;

}