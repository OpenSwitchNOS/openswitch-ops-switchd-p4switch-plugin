#ifndef __P4_TYPES_H__
#define __P4_TYPES_H__

/* OpenSwitch global defines. */
#define MAX_SWITCH_UNITS     1
#define MAX_SWITCH_UNIT_ID   (MAX_SWITCH_UNITS - 1)

typedef uint32_t p4_pbmp_t;
/*
 * Return the number of bits set in a unsigned int
 */
static inline int
_shr_popcount(unsigned int n)
{
    n = (n & 0x55555555) + ((n >> 1) & 0x55555555);
    n = (n & 0x33333333) + ((n >> 2) & 0x33333333);
    n = (n + (n >> 4)) & 0x0f0f0f0f;
    n = n + (n >> 8);

    return (n + (n >> 16)) & 0xff;
}

#define P4_SWITCH_API_DEFAULT_IP_PREFIX     32
#define P4_SWITCH_API_VXLAN_PROTOCOL        17
#define P4_SWITCH_API_AGE_INTERVAL          1800

#define _SHR_PBMP_PORT_MAX      32

#define _SHR_PBMP_WORD_MAX      1
#define _SHR_PBMP_WBIT(port)        (1U<<(port))
#define _SHR_PBMP_WORD_GET(pbm, word)   (pbm)
#define _SHR_PBMP_WORD_SET(pbm, word, val)  ((pbm) = (val))

#define _SHR_PBMP_CLEAR(pbm)        ((pbm) = 0)
#define _SHR_PBMP_MEMBER(bmp, port) (((bmp) & _SHR_PBMP_WBIT(port)) != 0)
#define _SHR_PBMP_COUNT(bmp, count) (count = _shr_popcount(bmp))
#define _SHR_PBMP_ITER(bmp, port) \
            for ((port) = 0; (port) < _SHR_PBMP_PORT_MAX; (port)++) \
            if (_SHR_PBMP_MEMBER((bmp), (port)))

#define _SHR_PBMP_IS_NULL(pbm)           ((pbm) == 0)
#define _SHR_PBMP_NOT_NULL(pbm)          ((pbm) != 0)
#define _SHR_PBMP_EQ(pbm_a, pbm_b)       ((pbm_a) == (pbm_b))
#define _SHR_PBMP_NEQ(pbm_a, pbm_b)      ((pbm_a) != (pbm_b))

/* Assignment operators */
#define _SHR_PBMP_ASSIGN(dst, src)       (dst) = (src)
#define _SHR_PBMP_AND(pbm_a, pbm_b)      ((pbm_a) &= (pbm_b))
#define _SHR_PBMP_OR(pbm_a, pbm_b)       ((pbm_a) |= (pbm_b))
#define _SHR_PBMP_XOR(pbm_a, pbm_b)      ((pbm_a) ^= (pbm_b))
#define _SHR_PBMP_REMOVE(pbm_a, pbm_b)   ((pbm_a) &= ~(pbm_b))
#define _SHR_PBMP_NEGATE(pbm_a, pbm_b)   ((pbm_a) = ~(pbm_b))

/* Port PBMP operators */
#define _SHR_PBMP_PORT_SET(pbm, port)    ((pbm) = (1U << (port)))
#define _SHR_PBMP_PORT_ADD(pbm, port)    ((pbm) |= (1U << (port)))
#define _SHR_PBMP_PORT_REMOVE(pbm, port) ((pbm) &= ~(1U << (port)))
#define _SHR_PBMP_PORT_FLIP(pbm, port)   ((pbm) ^= (1U << (port)))

#define P4_PBMP_PORT_MAX   _SHR_PBMP_PORT_MAX
#define P4_PBMP_CLEAR(pbm)  _SHR_PBMP_CLEAR(pbm)
#define P4_PBMP_MEMBER(bmp, port)  _SHR_PBMP_MEMBER((bmp), (port))
#define P4_PBMP_ITER(bmp, port)  _SHR_PBMP_ITER((bmp), (port))
#define P4_PBMP_COUNT(pbm, count)  _SHR_PBMP_COUNT(pbm, count)
#define P4_PBMP_IS_NULL(pbm)  _SHR_PBMP_IS_NULL(pbm)
#define P4_PBMP_NOT_NULL(pbm)  _SHR_PBMP_NOT_NULL(pbm)
#define P4_PBMP_EQ(pbm_a, pbm_b)  _SHR_PBMP_EQ(pbm_a, pbm_b)
#define P4_PBMP_NEQ(pbm_a, pbm_b)  _SHR_PBMP_NEQ(pbm_a, pbm_b)

#define P4_PBMP_ASSIGN(dst, src)  _SHR_PBMP_ASSIGN(dst, src)
#define P4_PBMP_AND(pbm_a, pbm_b)  _SHR_PBMP_AND(pbm_a, pbm_b)
#define P4_PBMP_OR(pbm_a, pbm_b)  _SHR_PBMP_OR(pbm_a, pbm_b)
#define P4_PBMP_XOR(pbm_a, pbm_b)  _SHR_PBMP_XOR(pbm_a, pbm_b)
#define P4_PBMP_REMOVE(pbm_a, pbm_b)  _SHR_PBMP_REMOVE(pbm_a, pbm_b)
#define P4_PBMP_NEGATE(pbm_a, pbm_b)  _SHR_PBMP_NEGATE(pbm_a, pbm_b)
#define P4_PBMP_PORT_SET(pbm, port)  _SHR_PBMP_PORT_SET(pbm, port)
#define P4_PBMP_PORT_ADD(pbm, port)  _SHR_PBMP_PORT_ADD(pbm, port)
#define P4_PBMP_PORT_REMOVE(pbm, port)  _SHR_PBMP_PORT_REMOVE(pbm, port)
#define P4_PBMP_PORT_FLIP(pbm, port)  _SHR_PBMP_PORT_FLIP(pbm, port)

#endif //__P4_TYPES_H__
