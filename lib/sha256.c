#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

#define SWAP32(x) ( x << 24 | x >> 24 | ( (x >> 8) & 0xff00 ) | ( (x & 0xff00) << 8 ) )
#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline uint32_t
get_be32( const void *p )
{
  return SWAP32( *(uint32_t *)p );
}

static inline void
put_be32( uint32_t val, void *p )
{
  *(uint32_t *)p = SWAP32( val );
}

struct sha256_state
{
  uint32_t           state[SHA256_DIGEST_SIZE / 4];
  uint32_t           count;
  uint8_t            buf[SHA256_BLOCK_SIZE];
};

static const uint32_t SHA256_K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t
Ch( uint32_t x, uint32_t y, uint32_t z )
{
  return z ^ ( x & ( y ^ z ) );
}

static inline uint32_t
Maj( uint32_t x, uint32_t y, uint32_t z )
{
  return ( x & y ) | ( z & ( x | y ) );
}

#define e0(x)	    (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define e1(x)	    (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define s0(x)	    (ROR32(x, 7) ^ ROR32(x, 18) ^ (x >> 3))
#define s1(x)	    (ROR32(x, 17) ^ ROR32(x, 19) ^ (x >> 10))

static inline void
LOAD_OP( int I, uint32_t *W, const uint8_t *input )
{
  W[I] = get_be32( ( uint32_t * ) input + I );
}

static inline void
BLEND_OP( int I, uint32_t *W )
{
  W[I] = s1( W[I - 2] ) + W[I - 7] + s0( W[I - 15] ) + W[I - 16];
}

#define SHA256_ROUND(i, a, b, c, d, e, f, g, h) do {		\
	uint32_t t1, t2;						\
	t1 = h + e1(e) + Ch(e, f, g) + SHA256_K[i] + W[i];	\
	t2 = e0(a) + Maj(a, b, c);				\
	d += t1;						\
	h = t1 + t2;						\
} while (0)

static void
sha256_transform( uint32_t *state, const uint8_t *input, uint32_t *W )
{
  uint32_t           a, b, c, d, e, f, g, h;
  int           i;

  /* load the input */
  for( i = 0; i < 16; i += 8 )
  {
    LOAD_OP( i + 0, W, input );
    LOAD_OP( i + 1, W, input );
    LOAD_OP( i + 2, W, input );
    LOAD_OP( i + 3, W, input );
    LOAD_OP( i + 4, W, input );
    LOAD_OP( i + 5, W, input );
    LOAD_OP( i + 6, W, input );
    LOAD_OP( i + 7, W, input );
  }

  /* now blend */
  for( i = 16; i < 64; i += 8 )
  {
    BLEND_OP( i + 0, W );
    BLEND_OP( i + 1, W );
    BLEND_OP( i + 2, W );
    BLEND_OP( i + 3, W );
    BLEND_OP( i + 4, W );
    BLEND_OP( i + 5, W );
    BLEND_OP( i + 6, W );
    BLEND_OP( i + 7, W );
  }

  /* load the state into our registers */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  /* now iterate */
  for( i = 0; i < 64; i += 8 )
  {
    SHA256_ROUND( i + 0, a, b, c, d, e, f, g, h );
    SHA256_ROUND( i + 1, h, a, b, c, d, e, f, g );
    SHA256_ROUND( i + 2, g, h, a, b, c, d, e, f );
    SHA256_ROUND( i + 3, f, g, h, a, b, c, d, e );
    SHA256_ROUND( i + 4, e, f, g, h, a, b, c, d );
    SHA256_ROUND( i + 5, d, e, f, g, h, a, b, c );
    SHA256_ROUND( i + 6, c, d, e, f, g, h, a, b );
    SHA256_ROUND( i + 7, b, c, d, e, f, g, h, a );
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void
sha256_update( struct sha256_state *sctx, const uint8_t *data, unsigned int len )
{
  unsigned int  partial, done;
  const uint8_t     *src;
  uint32_t           W[64];

  partial = sctx->count & 0x3f;
  sctx->count += len;
  done = 0;
  src = data;

  if( ( partial + len ) > 63 )
  {
    if( partial )
    {
      done = -partial;
      memcpy( sctx->buf + partial, data, done + 64 );
      src = sctx->buf;
    }

    do
    {
      sha256_transform( sctx->state, src, W );
      done += 64;
      src = data + done;
    }
    while( done + 63 < len );

    memset( W, 0, sizeof( W ) );

    partial = 0;
  }
  memcpy( sctx->buf + partial, src, len - done );
}

void
sha256_final( struct sha256_state *sctx, uint8_t *out )
{
  uint32_t          *dst = ( uint32_t * ) out;
  uint32_t           bits[2];
  unsigned int  index, pad_len;
  int           i;
  static const uint8_t padding[64] = { 0x80, };

  /* Save number of bits */
  bits[0] = 0;
  bits[1] = SWAP32( sctx->count << 3 );

  /* Pad out to 56 mod 64. */
  index = sctx->count & 0x3f;
  pad_len = ( index < 56 ) ? ( 56 - index ) : ( ( 64 + 56 ) - index );
  sha256_update( sctx, padding, pad_len );

  /* Append length (before padding) */
  sha256_update( sctx, ( const uint8_t * ) &bits, sizeof( bits ) );

  /* Store state in digest */
  for( i = 0; i < 8; i++ )
    put_be32( sctx->state[i], &dst[i] );

  /* Zeroize sensitive information. */
  memset( sctx, 0, sizeof( *sctx ) );
}

#define SHA256_H0	0x6a09e667UL
#define SHA256_H1	0xbb67ae85UL
#define SHA256_H2	0x3c6ef372UL
#define SHA256_H3	0xa54ff53aUL
#define SHA256_H4	0x510e527fUL
#define SHA256_H5	0x9b05688cUL
#define SHA256_H6	0x1f83d9abUL
#define SHA256_H7	0x5be0cd19UL

static inline void
sha256_init( struct sha256_state *sctx )
{
  sctx->state[0] = SHA256_H0;
  sctx->state[1] = SHA256_H1;
  sctx->state[2] = SHA256_H2;
  sctx->state[3] = SHA256_H3;
  sctx->state[4] = SHA256_H4;
  sctx->state[5] = SHA256_H5;
  sctx->state[6] = SHA256_H6;
  sctx->state[7] = SHA256_H7;
  sctx->count = 0;
}

void
sha256hash( const uint8_t *data, unsigned int len, uint8_t *out )
{
  struct sha256_state sctx;

  sha256_init( &sctx );
  sha256_update( &sctx, data, len );
  sha256_final( &sctx, out );
}
