#define _POSIX_C_SOURCE 200809L /* for posix_memalign() */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d /* corresponding ASC is 0 */

typedef unsigned int my_uint;   /* convenience to save a few line wraps */

FILE         *sg_warnings_strm = NULL;  /* would like to default to stderr */

int
pr2ws( const char *fmt, ... )
{
  va_list       args;
  int           n;

  va_start( args, fmt );
  n = vfprintf( sg_warnings_strm ? sg_warnings_strm : stderr, fmt, args );
  va_end( args );
  return n;
}

/* Users of the sg_pr2serr.h header need this function definition */
int
pr2serr( const char *fmt, ... )
{
  va_list       args;
  int           n;

  va_start( args, fmt );
  n = vfprintf( stderr, fmt, args );
  va_end( args );
  return n;
}

/* Want safe, 'n += snprintf(b + n, blen - n, ...)' style sequence of
 * functions. Returns number of chars placed in cp excluding the
 * trailing null char. So for cp_max_len > 0 the return value is always
 * < cp_max_len; for cp_max_len <= 1 the return value is 0 and no chars are
 * written to cp. Note this means that when cp_max_len = 1, this function
 * assumes that cp[0] is the null character and does nothing (and returns
 * 0). Linux kernel has a similar function called  scnprintf(). Public
 * declaration in sg_pr2serr.h header  */
int
sg_scnpr( char *cp, int cp_max_len, const char *fmt, ... )
{
  va_list       args;
  int           n;

  if( cp_max_len < 2 )
    return 0;
  va_start( args, fmt );
  n = vsnprintf( cp, cp_max_len, fmt, args );
  va_end( args );
  return ( n < cp_max_len ) ? n : ( cp_max_len - 1 );
}

/* Simple ASCII printable (does not use locale), includes space and excludes
 * DEL (0x7f). */
static inline int
my_isprint( int ch )
{
  return ( ( ch >= ' ' ) && ( ch < 0x7f ) );
}

/* Searches 'arr' for match on 'value' then 'peri_type'. If matches
   'value' but not 'peri_type' then yields first 'value' match entry.
   Last element of 'arr' has NULL 'name'. If no match returns NULL. */
static const struct sg_lib_value_name_t *
get_value_name( const struct sg_lib_value_name_t *arr, int value,
    int peri_type )
{
  const struct sg_lib_value_name_t *vp = arr;
  const struct sg_lib_value_name_t *holdp;

  if( peri_type < 0 )
    peri_type = 0;
  for( ; vp->name; ++vp )
  {
    if( value == vp->value )
    {
      if( peri_type == vp->peri_dev_type )
        return vp;
      holdp = vp;
      while( ( vp + 1 )->name && ( value == ( vp + 1 )->value ) )
      {
        ++vp;
        if( peri_type == vp->peri_dev_type )
          return vp;
      }
      return holdp;
    }
  }
  return NULL;
}

/* Take care to minimize printf() parsing delays when printing commands */
static char   bin2hexascii[] = { '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/* Given a SCSI command pointed to by cdbp of sz bytes this function forms
 * a SCSI command in ASCII surrounded by square brackets in 'b'. 'b' is at
 * least blen bytes long. If cmd_name is true then the command is prefixed
 * by its SCSI command name (e.g.  "VERIFY(10) [2f ...]". The command is
 * shown as spaced separated pairs of hexadecimal digits (i.e. 0-9, a-f).
 * Each pair represents byte. The leftmost pair of digits is cdbp[0] . If
 * sz <= 0 then this function tries to guess the length of the command. */
char         *
sg_get_command_str( const uint8_t *cdbp, int sz, bool cmd_name, int blen,
    char *b )
{
  int           k, j, jj;

  if( ( cdbp == NULL ) || ( b == NULL ) || ( blen < 1 ) )
    return b;
  if( cmd_name && ( blen > 16 ) )
  {
    sg_get_command_name( cdbp, 0, blen, b );
    j = ( int ) strlen( b );
    if( j < ( blen - 1 ) )
      b[j++] = ' ';
  }
  else
    j = 0;
  if( j >= blen )
    goto fini;
  b[j++] = '[';
  if( j >= blen )
    goto fini;
  if( sz <= 0 )
  {
    if( SG_VARIABLE_LENGTH_CMD == cdbp[0] )
      sz = cdbp[7] + 8;
    else
      sz = sg_get_command_size( cdbp[0] );
  }
  jj = j;
  for( k = 0; ( k < sz ) && ( j < ( blen - 3 ) ); ++k, j += 3, ++cdbp )
  {
    b[j] = bin2hexascii[( *cdbp >> 4 ) & 0xf];
    b[j + 1] = bin2hexascii[*cdbp & 0xf];
    b[j + 2] = ' ';
  }
  if( j > jj )
    --j;                        /* don't want trailing space before ']' */
  if( j >= blen )
    goto fini;
  b[j++] = ']';
fini:
  if( j >= blen )
    b[blen - 1] = '\0';         /* truncated string */
  else
    b[j] = '\0';
  return b;
}

#define CMD_NAME_LEN 128

void
sg_print_command_len( const uint8_t *cdbp, int sz )
{
  char          buff[CMD_NAME_LEN];

  sg_get_command_str( cdbp, sz, true, sizeof( buff ), buff );
  pr2ws( "%s\n", buff );
}

void
sg_print_command( const uint8_t *cdbp )
{
  sg_print_command_len( cdbp, 0 );
}

/* SCSI Status values */
static const struct sg_lib_simple_value_name_t sstatus_str_arr[] = {
  {0x0, "Good"},
  {0x2, "Check Condition"},
  {0x4, "Condition Met"},
  {0x8, "Busy"},
  {0x10, "Intermediate (obsolete)"},
  {0x14, "Intermediate-Condition Met (obsolete)"},
  {0x18, "Reservation Conflict"},
  {0x22, "Command terminated (obsolete)"},
  {0x28, "Task Set Full"},
  {0x30, "ACA Active"},
  {0x40, "Task Aborted"},
  {0xffff, NULL},
};

void
sg_get_scsi_status_str( int scsi_status, int buff_len, char *buff )
{
  const struct sg_lib_simple_value_name_t *sstatus_p;

  if( ( NULL == buff ) || ( buff_len < 1 ) )
    return;
  else if( 1 == buff_len )
  {
    buff[0] = '\0';
    return;
  }
  scsi_status &= 0x7e;          /* sanitize as much as possible */
  for( sstatus_p = sstatus_str_arr; sstatus_p->name; ++sstatus_p )
  {
    if( scsi_status == sstatus_p->value )
      break;
  }
  if( sstatus_p->name )
    sg_scnpr( buff, buff_len, "%s", sstatus_p->name );
  else
    sg_scnpr( buff, buff_len, "Unknown status [0x%x]", scsi_status );
}

/* Yield string associated with ASC/ASCQ values. Returns 'buff'. */
char         *
sg_get_asc_ascq_str( int asc, int ascq, int buff_len, char *buff )
{
  int           k, num, rlen;
  bool          found = false;
  struct sg_lib_asc_ascq_t *eip;
  struct sg_lib_asc_ascq_range_t *ei2p;

  if( 1 == buff_len )
  {
    buff[0] = '\0';
    return buff;
  }
  for( k = 0; sg_lib_asc_ascq_range[k].text; ++k )
  {
    ei2p = &sg_lib_asc_ascq_range[k];
    if( ( ei2p->asc == asc ) &&
        ( ascq >= ei2p->ascq_min ) && ( ascq <= ei2p->ascq_max ) )
    {
      found = true;
      num = sg_scnpr( buff, buff_len, "Additional sense: " );
      rlen = buff_len - num;
      sg_scnpr( buff + num, ( ( rlen > 0 ) ? rlen : 0 ), ei2p->text, ascq );
    }
  }
  if( found )
    return buff;

  for( k = 0; sg_lib_asc_ascq[k].text; ++k )
  {
    eip = &sg_lib_asc_ascq[k];
    if( eip->asc == asc && eip->ascq == ascq )
    {
      found = true;
      sg_scnpr( buff, buff_len, "Additional sense: %s", eip->text );
    }
  }
  if( !found )
  {
    if( asc >= 0x80 )
      sg_scnpr( buff, buff_len, "vendor specific ASC=%02x, ASCQ=%02x "
          "(hex)", asc, ascq );
    else if( ascq >= 0x80 )
      sg_scnpr( buff, buff_len, "ASC=%02x, vendor specific qualification "
          "ASCQ=%02x (hex)", asc, ascq );
    else
      sg_scnpr( buff, buff_len, "ASC=%02x, ASCQ=%02x (hex)", asc, ascq );
  }
  return buff;
}

/* Attempt to find the first SCSI sense data descriptor that matches the
 * given 'desc_type'. If found return pointer to start of sense data
 * descriptor; otherwise (including fixed format sense data) returns NULL. */
const uint8_t *
sg_scsi_sense_desc_find( const uint8_t *sbp, int sb_len, int desc_type )
{
  int           add_sb_len, add_d_len, desc_len, k;
  const uint8_t *descp;

  if( ( sb_len < 8 ) || ( 0 == ( add_sb_len = sbp[7] ) ) )
    return NULL;
  if( ( sbp[0] < 0x72 ) || ( sbp[0] > 0x73 ) )
    return NULL;
  add_sb_len = ( add_sb_len < ( sb_len - 8 ) ) ? add_sb_len : ( sb_len - 8 );
  descp = &sbp[8];
  for( desc_len = 0, k = 0; k < add_sb_len; k += desc_len )
  {
    descp += desc_len;
    add_d_len = ( k < ( add_sb_len - 1 ) ) ? descp[1] : -1;
    desc_len = add_d_len + 2;
    if( descp[0] == desc_type )
      return descp;
    if( add_d_len < 0 )         /* short descriptor ?? */
      break;
  }
  return NULL;
}

/* Returns true if SKSV is set and sense key is NO_SENSE or NOT_READY. Also
 * returns true if progress indication sense data descriptor found. Places
 * progress field from sense data where progress_outp points. If progress
 * field is not available returns false and *progress_outp is unaltered.
 * Handles both fixed and descriptor sense formats.
 * Hint: if true is returned *progress_outp may be multiplied by 100 then
 * divided by 65536 to get the percentage completion. */
bool
sg_get_sense_progress_fld( const uint8_t *sbp, int sb_len,
    int *progress_outp )
{
  const uint8_t *bp;
  int           sk, sk_pr;

  if( sb_len < 7 )
    return false;
  switch ( sbp[0] & 0x7f )
  {
    case 0x70:
    case 0x71:
      sk = ( sbp[2] & 0xf );
      if( ( sb_len < 18 ) ||
          ( ( SPC_SK_NO_SENSE != sk ) && ( SPC_SK_NOT_READY != sk ) ) )
        return false;
      if( sbp[15] & 0x80 )
      {                         /* SKSV bit set */
        if( progress_outp )
          *progress_outp = sg_get_unaligned_be16( sbp + 16 );
        return true;
      }
      else
        return false;
    case 0x72:
    case 0x73:
      /* sense key specific progress (0x2) or progress descriptor (0xa) */
      sk = ( sbp[1] & 0xf );
      sk_pr = ( SPC_SK_NO_SENSE == sk ) || ( SPC_SK_NOT_READY == sk );
      if( sk_pr && ( ( bp = sg_scsi_sense_desc_find( sbp, sb_len, 2 ) ) ) &&
          ( 0x6 == bp[1] ) && ( 0x80 & bp[4] ) )
      {
        if( progress_outp )
          *progress_outp = sg_get_unaligned_be16( bp + 5 );
        return true;
      }
      else if( ( ( bp = sg_scsi_sense_desc_find( sbp, sb_len, 0xa ) ) ) &&
          ( ( 0x6 == bp[1] ) ) )
      {
        if( progress_outp )
          *progress_outp = sg_get_unaligned_be16( bp + 6 );
        return true;
      }
      else
        return false;
    default:
      return false;
  }
}

char         *
sg_get_pdt_str( int pdt, int buff_len, char *buff )
{
  if( ( pdt < 0 ) || ( pdt > 31 ) )
    sg_scnpr( buff, buff_len, "bad pdt" );
  else
    sg_scnpr( buff, buff_len, "%s", sg_lib_pdt_strs[pdt] );
  return buff;
}

int
sg_lib_pdt_decay( int pdt )
{
  if( ( pdt < 0 ) || ( pdt > 31 ) )
    return 0;
  return sg_lib_pdt_decay_arr[pdt];
}

char         *
sg_get_trans_proto_str( int tpi, int buff_len, char *buff )
{
  if( ( tpi < 0 ) || ( tpi > 15 ) )
    sg_scnpr( buff, buff_len, "bad tpi" );
  else
    sg_scnpr( buff, buff_len, "%s", sg_lib_transport_proto_strs[tpi] );
  return buff;
}

static const char *desig_code_set_str_arr[] = {
  "Reserved [0x0]",
  "Binary",
  "ASCII",
  "UTF-8",
  "Reserved [0x4]", "Reserved [0x5]", "Reserved [0x6]", "Reserved [0x7]",
  "Reserved [0x8]", "Reserved [0x9]", "Reserved [0xa]", "Reserved [0xb]",
  "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

const char   *
sg_get_desig_code_set_str( int val )
{
  if( ( val >= 0 )
      && ( val < ( int ) SG_ARRAY_SIZE( desig_code_set_str_arr ) ) )
    return desig_code_set_str_arr[val];
  else
    return NULL;
}

static const char *desig_assoc_str_arr[] = {
  "Addressed logical unit",
  "Target port",                /* that received request; unless SCSI ports VPD */
  "Target device that contains addressed lu",
  "Reserved [0x3]",
};

const char   *
sg_get_desig_assoc_str( int val )
{
  if( ( val >= 0 ) && ( val < ( int ) SG_ARRAY_SIZE( desig_assoc_str_arr ) ) )
    return desig_assoc_str_arr[val];
  else
    return NULL;
}

static const char *desig_type_str_arr[] = {
  "vendor specific [0x0]",
  "T10 vendor identification",
  "EUI-64 based",
  "NAA",
  "Relative target port",
  "Target port group",          /* spc4r09: _primary_ target port group */
  "Logical unit group",
  "MD5 logical unit identifier",
  "SCSI name string",
  "Protocol specific port identifier",  /* spc4r36 */
  "UUID identifier",            /* spc5r08 */
  "Reserved [0xb]",
  "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

const char   *
sg_get_desig_type_str( int val )
{
  if( ( val >= 0 ) && ( val < ( int ) SG_ARRAY_SIZE( desig_type_str_arr ) ) )
    return desig_type_str_arr[val];
  else
    return NULL;
}

/* Fetch sense information */
int
sg_get_sense_str( const char *lip, const uint8_t *sbp, int sb_len,
    bool raw_sinfo, int cblen, char *cbp )
{
  bool          descriptor_format = false;
  bool          sdat_ovfl = false;
  bool          valid;
  int           len, progress, n, r, pr, rem, blen;
  unsigned int  info;
  uint8_t       resp_code;
  const char   *ebp = NULL;
  char          ebuff[64];
  char          b[256];
  struct sg_scsi_sense_hdr ssh;

  if( ( NULL == cbp ) || ( cblen <= 0 ) )
    return 0;
  else if( 1 == cblen )
  {
    cbp[0] = '\0';
    return 0;
  }
  blen = sizeof( b );
  n = 0;
  if( NULL == lip )
    lip = "";
  if( ( NULL == sbp ) || ( sb_len < 1 ) )
  {
    n += sg_scnpr( cbp, cblen, "%s >>> sense buffer empty\n", lip );
    return n;
  }
  resp_code = 0x7f & sbp[0];
  valid = !!( sbp[0] & 0x80 );
  len = sb_len;
  if( sg_scsi_normalize_sense( sbp, sb_len, &ssh ) )
  {
    switch ( ssh.response_code )
    {
      case 0x70:               /* fixed, current */
        ebp = "Fixed format, current";
        len = ( sb_len > 7 ) ? ( sbp[7] + 8 ) : sb_len;
        len = ( len > sb_len ) ? sb_len : len;
        sdat_ovfl = ( len > 2 ) ? !!( sbp[2] & 0x10 ) : false;
        break;
      case 0x71:               /* fixed, deferred */
        /* error related to a previous command */
        ebp = "Fixed format, <<<deferred>>>";
        len = ( sb_len > 7 ) ? ( sbp[7] + 8 ) : sb_len;
        len = ( len > sb_len ) ? sb_len : len;
        sdat_ovfl = ( len > 2 ) ? !!( sbp[2] & 0x10 ) : false;
        break;
      case 0x72:               /* descriptor, current */
        descriptor_format = true;
        ebp = "Descriptor format, current";
        sdat_ovfl = ( sb_len > 4 ) ? !!( sbp[4] & 0x80 ) : false;
        break;
      case 0x73:               /* descriptor, deferred */
        descriptor_format = true;
        ebp = "Descriptor format, <<<deferred>>>";
        sdat_ovfl = ( sb_len > 4 ) ? !!( sbp[4] & 0x80 ) : false;
        break;
      case 0x0:
        ebp = "Response code: 0x0 (?)";
        break;
      default:
        sg_scnpr( ebuff, sizeof( ebuff ), "Unknown response code: 0x%x",
            ssh.response_code );
        ebp = ebuff;
        break;
    }
    n += sg_scnpr( cbp + n, cblen - n, "%s%s; Sense key: %s\n", lip, ebp,
        sg_lib_sense_key_desc[ssh.sense_key] );
    if( sdat_ovfl )
      n += sg_scnpr( cbp + n, cblen - n, "%s<<<Sense data overflow "
          "(SDAT_OVFL)>>>\n", lip );
    if( descriptor_format )
    {
      n += sg_scnpr( cbp + n, cblen - n, "%s%s\n", lip,
          sg_get_asc_ascq_str( ssh.asc, ssh.ascq, blen, b ) );
    }
    else if( ( len > 12 ) && ( 0 == ssh.asc ) &&
        ( ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq ) )
    {
      /* SAT ATA PASS-THROUGH fixed format */
      n += sg_scnpr( cbp + n, cblen - n, "%s%s\n", lip,
          sg_get_asc_ascq_str( ssh.asc, ssh.ascq, blen, b ) );
    }
    else if( len > 2 )
    {                           /* fixed format */
      if( len > 12 )
        n += sg_scnpr( cbp + n, cblen - n, "%s%s\n", lip,
            sg_get_asc_ascq_str( ssh.asc, ssh.ascq, blen, b ) );
      r = 0;
      if( strlen( lip ) > 0 )
        r += sg_scnpr( b + r, blen - r, "%s", lip );
      if( len > 6 )
      {
        info = sg_get_unaligned_be32( sbp + 3 );
        if( valid )
          r += sg_scnpr( b + r, blen - r, "  Info fld=0x%x [%u] ",
              info, info );
        else if( info > 0 )
          r += sg_scnpr( b + r, blen - r, "  Valid=0, Info fld=0x%x "
              "[%u] ", info, info );
      }
      else
        info = 0;
      if( sbp[2] & 0xe0 )
      {
        if( sbp[2] & 0x80 )
          r += sg_scnpr( b + r, blen - r, " FMK" );
        /* current command has read a filemark */
        if( sbp[2] & 0x40 )
          r += sg_scnpr( b + r, blen - r, " EOM" );
        /* end-of-medium condition exists */
        if( sbp[2] & 0x20 )
          r += sg_scnpr( b + r, blen - r, " ILI" );
        /* incorrect block length requested */
        r += sg_scnpr( b + r, blen - r, "\n" );
      }
      else if( valid || ( info > 0 ) )
        r += sg_scnpr( b + r, blen - r, "\n" );
      if( ( len >= 14 ) && sbp[14] )
        r += sg_scnpr( b + r, blen - r, "%s  Field replaceable unit "
            "code: %d\n", lip, sbp[14] );
      if( ( len >= 18 ) && ( sbp[15] & 0x80 ) )
      {
        /* sense key specific decoding */
        switch ( ssh.sense_key )
        {
          case SPC_SK_ILLEGAL_REQUEST:
            r += sg_scnpr( b + r, blen - r, "%s	Sense Key Specific: "
                "Error in %s: byte %d", lip,
                ( ( sbp[15] & 0x40 ) ?
                "Command" : "Data parameters" ),
                sg_get_unaligned_be16( sbp + 16 ) );
            if( sbp[15] & 0x08 )
              r += sg_scnpr( b + r, blen - r, " bit %d\n", sbp[15] & 0x07 );
            else
              r += sg_scnpr( b + r, blen - r, "\n" );
            break;
          case SPC_SK_NO_SENSE:
          case SPC_SK_NOT_READY:
            progress = sg_get_unaligned_be16( sbp + 16 );
            pr = ( progress * 100 ) / 65536;
            rem = ( ( progress * 100 ) % 65536 ) / 656;
            r += sg_scnpr( b + r, blen - r, "%s	Progress indication: "
                "%d.%02d%%\n", lip, pr, rem );
            break;
          case SPC_SK_HARDWARE_ERROR:
          case SPC_SK_MEDIUM_ERROR:
          case SPC_SK_RECOVERED_ERROR:
            r += sg_scnpr( b + r, blen - r, "%s	Actual retry count: "
                "0x%02x%02x\n", lip, sbp[16], sbp[17] );
            break;
          case SPC_SK_COPY_ABORTED:
            r += sg_scnpr( b + r, blen - r, "%s	Segment pointer: ", lip );
            r += sg_scnpr( b + r, blen - r, "Relative to start of %s, "
                "byte %d", ( ( sbp[15] & 0x20 ) ?
                "segment descriptor" : "parameter list" ),
                sg_get_unaligned_be16( sbp + 16 ) );
            if( sbp[15] & 0x08 )
              r += sg_scnpr( b + r, blen - r, " bit %d\n", sbp[15] & 0x07 );
            else
              r += sg_scnpr( b + r, blen - r, "\n" );
            break;
          case SPC_SK_UNIT_ATTENTION:
            r += sg_scnpr( b + r, blen - r, "%s	Unit attention "
                "condition queue: ", lip );
            r += sg_scnpr( b + r, blen - r, "overflow flag is %d\n",
                !!( sbp[15] & 0x1 ) );
            break;
          default:
            r += sg_scnpr( b + r, blen - r, "%s	Sense_key: 0x%x "
                "unexpected\n", lip, ssh.sense_key );
            break;
        }
      }
      if( r > 0 )
        n += sg_scnpr( cbp + n, cblen - n, "%s", b );
    }
    else
      n += sg_scnpr( cbp + n, cblen - n, "%s fixed descriptor length "
          "too short, len=%d\n", lip, len );
  }
  else
  {                             /* unable to normalise sense buffer, something irregular */
    if( sb_len < 4 )
    {                           /* Too short */
      n += sg_scnpr( cbp + n, cblen - n, "%ssense buffer too short (4 "
          "byte minimum)\n", lip );
      goto check_raw;
    }
    if( 0x7f == resp_code )
    {                           /* Vendor specific */
      n += sg_scnpr( cbp + n, cblen - n, "%sVendor specific sense "
          "buffer, in hex:\n", lip );
      n += hex2str( sbp, sb_len, lip, -1, cblen - n, cbp + n );
      return n;                 /* no need to check raw, just output in hex */
    }
    /* non-extended SCSI-1 sense data ?? */
    r = 0;
    if( strlen( lip ) > 0 )
      r += sg_scnpr( b + r, blen - r, "%s", lip );
    r += sg_scnpr( b + r, blen - r, "Probably uninitialized data.\n%s  "
        "Try to view as SCSI-1 non-extended sense:\n", lip );
    r += sg_scnpr( b + r, blen - r, "  AdValid=%d  Error class=%d  Error "
        "code=%d\n", valid, ( ( sbp[0] >> 4 ) & 0x7 ), ( sbp[0] & 0xf ) );
    if( valid )
      sg_scnpr( b + r, blen - r, "%s  lba=0x%x\n", lip,
          sg_get_unaligned_be24( sbp + 1 ) & 0x1fffff );
    n += sg_scnpr( cbp + n, cblen - n, "%s\n", b );
  }
check_raw:
  if( raw_sinfo )
  {
    int           embed_len;
    char          z[64];

    n += sg_scnpr( cbp + n, cblen - n, "%s Raw sense data (in hex), "
        "sb_len=%d", lip, sb_len );
    if( n >= ( cblen - 1 ) )
      return n;
    if( ( sb_len > 7 ) && ( sbp[0] >= 0x70 ) && ( sbp[0] < 0x74 ) )
    {
      embed_len = sbp[7] + 8;
      n += sg_scnpr( cbp + n, cblen - n, ", embedded_len=%d\n", embed_len );
    }
    else
    {
      embed_len = sb_len;
      n += sg_scnpr( cbp + n, cblen - n, "\n" );
    }
    if( n >= ( cblen - 1 ) )
      return n;

    sg_scnpr( z, sizeof( z ), "%.50s	     ", lip );
    n += hex2str( sbp, embed_len, z, -1, cblen - n, cbp + n );
  }
  return n;
}

/* Print sense information */
void
sg_print_sense( const char *leadin, const uint8_t *sbp, int sb_len,
    bool raw_sinfo )
{
  uint32_t      pg_sz = sg_get_page_size(  );
  char         *cp;
  uint8_t      *free_cp;

  cp = ( char * ) sg_memalign( pg_sz, pg_sz, &free_cp, false );
  if( NULL == cp )
    return;
  sg_get_sense_str( leadin, sbp, sb_len, raw_sinfo, pg_sz, cp );
  pr2ws( "%s", cp );
  free( free_cp );
}

/* This examines exit_status and if an error message is known it is output
 * as a string to 'b' and true is returned. If 'longer' is true and extra
 * information is available then it is added to the output. If no error
 * message is available a null character is output and false is returned.
 * If exit_status is zero (no error) and 'longer' is true then the string
 * 'No errors' is output; if 'longer' is false then a null character is
 * output; in both cases true is returned. If exit_status is negative then
 * a null character is output and false is returned. All messages are a
 * single line (less than 80 characters) with no trailing LF. The output
 * string including the trailing null character is no longer than b_len.
 * exit_status represents the Unix exit status available after a utility
 * finishes executing (for whatever reason). */
bool
sg_exit2str( int exit_status, bool longer, int b_len, char *b )
{
  const struct sg_value_2names_t *ess = sg_exit_str_arr;

  if( ( b_len < 1 ) || ( NULL == b ) )
    return false;
  /* if there is a valid buffer, initialize it to a valid empty string */
  b[0] = '\0';
  if( exit_status < 0 )
    return false;
  else if( ( 0 == exit_status ) || ( SG_LIB_OK_FALSE == exit_status ) )
  {
    if( longer )
      goto fini;
    return true;
  }

  if( ( exit_status > SG_LIB_OS_BASE_ERR ) &&   /* 51 to 96 inclusive */
      ( exit_status < SG_LIB_CAT_MALFORMED ) )
  {
    snprintf( b, b_len, "%s%s", ( longer ? "OS error: " : "" ),
        safe_strerror( exit_status - SG_LIB_OS_BASE_ERR ) );
    return true;
  }
  else if( ( exit_status > 128 ) && ( exit_status < 255 ) )
  {
    snprintf( b, b_len, "Utility stopped/aborted by signal number: %d",
        exit_status - 128 );
    return true;
  }
fini:
  for( ; ess->name; ++ess )
  {
    if( exit_status == ess->value )
      break;
  }
  if( ess->name )
  {
    if( longer && ess->name2 )
      snprintf( b, b_len, "%s, %s", ess->name, ess->name2 );
    else
      snprintf( b, b_len, "%s", ess->name );
    return true;
  }
  return false;
}

static bool
sg_if_can2fp( const char *leadin, int exit_status, FILE *fp )
{
  char          b[256];
  const char   *s = leadin ? leadin : "";

  if( ( 0 == exit_status ) || ( SG_LIB_OK_FALSE == exit_status ) )
    return true;                /* don't print anything */
  else if( sg_exit2str( exit_status, false, sizeof( b ), b ) )
  {
    fprintf( fp, "%s%s\n", s, b );
    return true;
  }
  else
    return false;
}

/* This examines exit_status and if an error message is known it is output
 * to stdout/stderr and true is returned. If no error message is
 * available nothing is output and false is returned. If exit_status is
 * zero (no error) nothing is output and true is returned. If exit_status
 * is negative then nothing is output and false is returned. If leadin is
 * non-NULL then it is printed before the error message. All messages are
 * a single line with a trailing LF. */
bool
sg_if_can2stdout( const char *leadin, int exit_status )
{
  return sg_if_can2fp( leadin, exit_status, stdout );
}

/* See sg_if_can2stdout() comments */
bool
sg_if_can2stderr( const char *leadin, int exit_status )
{
  return sg_if_can2fp( leadin, exit_status,
      sg_warnings_strm ? sg_warnings_strm : stderr );
}

/* If os_err_num is within bounds then the returned value is 'os_err_num +
 * SG_LIB_OS_BASE_ERR' otherwise SG_LIB_OS_BASE_ERR is returned. If
 * os_err_num is 0 then 0 is returned. */
int
sg_convert_errno( int os_err_num )
{
  if( os_err_num <= 0 )
  {
    if( os_err_num < 0 )
      return SG_LIB_OS_BASE_ERR;
    return os_err_num;          /* os_err_num of 0 maps to 0 */
  }
  if( os_err_num < ( SG_LIB_CAT_MALFORMED - SG_LIB_OS_BASE_ERR ) )
    return SG_LIB_OS_BASE_ERR + os_err_num;
  return SG_LIB_OS_BASE_ERR;
}

static const char *const bad_sense_cat = "Bad sense category";

/* Yield string associated with sense category. Returns 'b' (or pointer
 * to "Bad sense category" if 'b' is NULL). If sense_cat unknown then
 * yield "Sense category: <sense_cat_val>" string. The original 'sense
 * category' concept has been expanded to most detected errors and is
 * returned by these utilities as their exit status value (an (unsigned)
 * 8 bit value where 0 means good (i.e. no errors)).  Uses sg_exit2str()
 * function. */
const char   *
sg_get_category_sense_str( int sense_cat, int b_len, char *b, int verbose )
{
  int           n;

  if( NULL == b )
    return bad_sense_cat;
  if( b_len <= 0 )
    return b;
  if( !sg_exit2str( sense_cat, ( verbose > 0 ), b_len, b ) )
  {
    n = sg_scnpr( b, b_len, "Sense category: %d", sense_cat );
    if( ( 0 == verbose ) && ( n < ( b_len - 1 ) ) )
      sg_scnpr( b + n, b_len - n, ", try '-v' option for more "
          "information" );
  }
  return b;                     /* Note that a valid C string is returned in all cases */
}

/* See description in sg_lib.h header file */
bool
sg_scsi_normalize_sense( const uint8_t *sbp, int sb_len,
    struct sg_scsi_sense_hdr *sshp )
{
  uint8_t       resp_code;
  if( sshp )
    memset( sshp, 0, sizeof( struct sg_scsi_sense_hdr ) );
  if( ( NULL == sbp ) || ( sb_len < 1 ) )
    return false;
  resp_code = 0x7f & sbp[0];
  if( ( resp_code < 0x70 ) || ( resp_code > 0x73 ) )
    return false;
  if( sshp )
  {
    sshp->response_code = resp_code;
    if( sshp->response_code >= 0x72 )
    {                           /* descriptor format */
      if( sb_len > 1 )
        sshp->sense_key = ( 0xf & sbp[1] );
      if( sb_len > 2 )
        sshp->asc = sbp[2];
      if( sb_len > 3 )
        sshp->ascq = sbp[3];
      if( sb_len > 7 )
        sshp->additional_length = sbp[7];
      sshp->byte4 = sbp[4];     /* bit 7: SDAT_OVFL bit */
      /* sbp[5] and sbp[6] reserved for descriptor format */
    }
    else
    {                           /* fixed format */
      if( sb_len > 2 )
        sshp->sense_key = ( 0xf & sbp[2] );
      if( sb_len > 7 )
      {
        sb_len = ( sb_len < ( sbp[7] + 8 ) ) ? sb_len : ( sbp[7] + 8 );
        if( sb_len > 12 )
          sshp->asc = sbp[12];
        if( sb_len > 13 )
          sshp->ascq = sbp[13];
      }
      if( sb_len > 6 )
      {                         /* lower 3 bytes of INFO field */
        sshp->byte4 = sbp[4];
        sshp->byte5 = sbp[5];
        sshp->byte6 = sbp[6];
      }
    }
  }
  return true;
}

/* Returns a SG_LIB_CAT_* value. If cannot decode sense buffer (sbp) or a
 * less common sense key then return SG_LIB_CAT_SENSE .*/
int
sg_err_category_sense( const uint8_t *sbp, int sb_len )
{
  struct sg_scsi_sense_hdr ssh;

  if( ( sbp && ( sb_len > 2 ) ) &&
      ( sg_scsi_normalize_sense( sbp, sb_len, &ssh ) ) )
  {
    switch ( ssh.sense_key )
    {                           /* 0 to 0x1f */
      case SPC_SK_NO_SENSE:
        return SG_LIB_CAT_NO_SENSE;
      case SPC_SK_RECOVERED_ERROR:
        return SG_LIB_CAT_RECOVERED;
      case SPC_SK_NOT_READY:
        return SG_LIB_CAT_NOT_READY;
      case SPC_SK_MEDIUM_ERROR:
      case SPC_SK_HARDWARE_ERROR:
      case SPC_SK_BLANK_CHECK:
        return SG_LIB_CAT_MEDIUM_HARD;
      case SPC_SK_UNIT_ATTENTION:
        return SG_LIB_CAT_UNIT_ATTENTION;
        /* used to return SG_LIB_CAT_MEDIA_CHANGED when ssh.asc==0x28 */
      case SPC_SK_ILLEGAL_REQUEST:
        if( ( 0x20 == ssh.asc ) && ( 0x0 == ssh.ascq ) )
          return SG_LIB_CAT_INVALID_OP;
        else if( ( 0x21 == ssh.asc ) && ( 0x0 == ssh.ascq ) )
          return SG_LIB_LBA_OUT_OF_RANGE;
        else
          return SG_LIB_CAT_ILLEGAL_REQ;
        break;
      case SPC_SK_ABORTED_COMMAND:
        if( 0x10 == ssh.asc )
          return SG_LIB_CAT_PROTECTION;
        else
          return SG_LIB_CAT_ABORTED_COMMAND;
      case SPC_SK_MISCOMPARE:
        return SG_LIB_CAT_MISCOMPARE;
      case SPC_SK_DATA_PROTECT:
        return SG_LIB_CAT_DATA_PROTECT;
      case SPC_SK_COPY_ABORTED:
        return SG_LIB_CAT_COPY_ABORTED;
      case SPC_SK_COMPLETED:
      case SPC_SK_VOLUME_OVERFLOW:
        return SG_LIB_CAT_SENSE;
      default:
        ;                       /* reserved and vendor specific sense keys fall through */
    }
  }
  return SG_LIB_CAT_SENSE;
}

/* Beware: gives wrong answer for variable length command (opcode=0x7f) */
int
sg_get_command_size( uint8_t opcode )
{
  switch ( ( opcode >> 5 ) & 0x7 )
  {
    case 0:
      return 6;
    case 3:
    case 5:
      return 12;
    case 4:
      return 16;
    default:                   /* 1, 2, 6, 7 */
      return 10;
  }
}

void
sg_get_command_name( const uint8_t *cdbp, int peri_type, int buff_len,
    char *buff )
{
  int           service_action;

  if( ( NULL == buff ) || ( buff_len < 1 ) )
    return;
  else if( 1 == buff_len )
  {
    buff[0] = '\0';
    return;
  }
  if( NULL == cdbp )
  {
    sg_scnpr( buff, buff_len, "%s", "<null> command pointer" );
    return;
  }
  service_action = ( SG_VARIABLE_LENGTH_CMD == cdbp[0] ) ?
      sg_get_unaligned_be16( cdbp + 8 ) : ( cdbp[1] & 0x1f );
  sg_get_opcode_sa_name( cdbp[0], service_action, peri_type, buff_len, buff );
}

struct op_code2sa_t
{
  int           op_code;
  int           pdt_match;      /* -1->all; 0->disk,ZBC,RCB, 1->tape+adc+smc */
  struct sg_lib_value_name_t *arr;
  const char   *prefix;
};

static struct op_code2sa_t op_code2sa_arr[] = {
  {SG_VARIABLE_LENGTH_CMD, -1, sg_lib_variable_length_arr, NULL},
  {SG_MAINTENANCE_IN, -1, sg_lib_maint_in_arr, NULL},
  {SG_MAINTENANCE_OUT, -1, sg_lib_maint_out_arr, NULL},
  {SG_SERVICE_ACTION_IN_12, -1, sg_lib_serv_in12_arr, NULL},
  {SG_SERVICE_ACTION_OUT_12, -1, sg_lib_serv_out12_arr, NULL},
  {SG_SERVICE_ACTION_IN_16, -1, sg_lib_serv_in16_arr, NULL},
  {SG_SERVICE_ACTION_OUT_16, -1, sg_lib_serv_out16_arr, NULL},
  {SG_SERVICE_ACTION_BIDI, -1, sg_lib_serv_bidi_arr, NULL},
  {SG_PERSISTENT_RESERVE_IN, -1, sg_lib_pr_in_arr, "Persistent reserve in"},
  {SG_PERSISTENT_RESERVE_OUT, -1, sg_lib_pr_out_arr,
      "Persistent reserve out"},
  {SG_3PARTY_COPY_OUT, -1, sg_lib_xcopy_sa_arr, NULL},
  {SG_3PARTY_COPY_IN, -1, sg_lib_rec_copy_sa_arr, NULL},
  {SG_READ_BUFFER, -1, sg_lib_read_buff_arr, "Read buffer(10)"},
  {SG_READ_BUFFER_16, -1, sg_lib_read_buff_arr, "Read buffer(16)"},
  {SG_READ_ATTRIBUTE, -1, sg_lib_read_attr_arr, "Read attribute"},
  {SG_READ_POSITION, 1, sg_lib_read_pos_arr, "Read position"},
  {SG_SANITIZE, 0, sg_lib_sanitize_sa_arr, "Sanitize"},
  {SG_WRITE_BUFFER, -1, sg_lib_write_buff_arr, "Write buffer"},
  {SG_ZONING_IN, 0, sg_lib_zoning_in_arr, NULL},
  {SG_ZONING_OUT, 0, sg_lib_zoning_out_arr, NULL},
  {0xffff, -1, NULL, NULL},
};

void
sg_get_opcode_sa_name( uint8_t cmd_byte0, int service_action,
    int peri_type, int buff_len, char *buff )
{
  int           d_pdt;
  const struct sg_lib_value_name_t *vnp;
  const struct op_code2sa_t *osp;
  char          b[80];

  if( ( NULL == buff ) || ( buff_len < 1 ) )
    return;
  else if( 1 == buff_len )
  {
    buff[0] = '\0';
    return;
  }

  if( peri_type < 0 )
    peri_type = 0;
  d_pdt = sg_lib_pdt_decay( peri_type );
  for( osp = op_code2sa_arr; osp->arr; ++osp )
  {
    if( ( int ) cmd_byte0 == osp->op_code )
    {
      if( ( osp->pdt_match < 0 ) || ( d_pdt == osp->pdt_match ) )
      {
        vnp = get_value_name( osp->arr, service_action, peri_type );
        if( vnp )
        {
          if( osp->prefix )
            sg_scnpr( buff, buff_len, "%s, %s", osp->prefix, vnp->name );
          else
            sg_scnpr( buff, buff_len, "%s", vnp->name );
        }
        else
        {
          sg_get_opcode_name( cmd_byte0, peri_type, sizeof( b ), b );
          sg_scnpr( buff, buff_len, "%s service action=0x%x", b,
              service_action );
        }
      }
      else
        sg_get_opcode_name( cmd_byte0, peri_type, buff_len, buff );
      return;
    }
  }
  sg_get_opcode_name( cmd_byte0, peri_type, buff_len, buff );
}

void
sg_get_opcode_name( uint8_t cmd_byte0, int peri_type, int buff_len,
    char *buff )
{
  const struct sg_lib_value_name_t *vnp;
  int           grp;

  if( ( NULL == buff ) || ( buff_len < 1 ) )
    return;
  else if( 1 == buff_len )
  {
    buff[0] = '\0';
    return;
  }
  if( SG_VARIABLE_LENGTH_CMD == cmd_byte0 )
  {
    sg_scnpr( buff, buff_len, "%s", "Variable length" );
    return;
  }
  grp = ( cmd_byte0 >> 5 ) & 0x7;
  switch ( grp )
  {
    case 0:
    case 1:
    case 2:
    case 4:
    case 5:
      vnp = get_value_name( sg_lib_normal_opcodes, cmd_byte0, peri_type );
      if( vnp )
        sg_scnpr( buff, buff_len, "%s", vnp->name );
      else
        sg_scnpr( buff, buff_len, "Opcode=0x%x", ( int ) cmd_byte0 );
      break;
    case 3:
      sg_scnpr( buff, buff_len, "Reserved [0x%x]", ( int ) cmd_byte0 );
      break;
    case 6:
    case 7:
      sg_scnpr( buff, buff_len, "Vendor specific [0x%x]", ( int ) cmd_byte0 );
      break;
  }
}

/* Fetch NVMe command name given first byte (byte offset 0 in 64 byte
 * command) of command. Gets Admin NVMe command name if 'admin' is true
 * (e.g. opcode=0x6 -> Identify), otherwise gets NVM command set name
 * (e.g. opcode=0 -> Flush). Returns 'buff'. */
char         *
sg_get_nvme_opcode_name( uint8_t cmd_byte0, bool admin, int buff_len,
    char *buff )
{
  const struct sg_lib_simple_value_name_t *vnp = admin ?
      sg_lib_nvme_admin_cmd_arr : sg_lib_nvme_nvm_cmd_arr;

  if( ( NULL == buff ) || ( buff_len < 1 ) )
    return buff;
  else if( 1 == buff_len )
  {
    buff[0] = '\0';
    return buff;
  }
  for( ; vnp->name; ++vnp )
  {
    if( cmd_byte0 == ( uint8_t ) vnp->value )
    {
      snprintf( buff, buff_len, "%s", vnp->name );
      return buff;
    }
  }
  if( admin )
  {
    if( cmd_byte0 >= 0xc0 )
      snprintf( buff, buff_len, "Vendor specific opcode: 0x%x", cmd_byte0 );
    else if( cmd_byte0 >= 0x80 )
      snprintf( buff, buff_len, "Command set specific opcode: 0x%x",
          cmd_byte0 );
    else
      snprintf( buff, buff_len, "Unknown opcode: 0x%x", cmd_byte0 );
  }
  else
  {                             /* NVM (non-Admin) command set */
    if( cmd_byte0 >= 0x80 )
      snprintf( buff, buff_len, "Vendor specific opcode: 0x%x", cmd_byte0 );
    else
      snprintf( buff, buff_len, "Unknown opcode: 0x%x", cmd_byte0 );
  }
  return buff;
}

/* Iterates to next designation descriptor in the device identification
 * VPD page. The 'initial_desig_desc' should point to start of first
 * descriptor with 'page_len' being the number of valid bytes in that
 * and following descriptors. To start, 'off' should point to a negative
 * value, thereafter it should point to the value yielded by the previous
 * call. If 0 returned then 'initial_desig_desc + *off' should be a valid
 * descriptor; returns -1 if normal end condition and -2 for an abnormal
 * termination. Matches association, designator_type and/or code_set when
 * any of those values are greater than or equal to zero. */
int
sg_vpd_dev_id_iter( const uint8_t *initial_desig_desc, int page_len,
    int *off, int m_assoc, int m_desig_type, int m_code_set )
{
  bool          fltr = ( ( m_assoc >= 0 ) || ( m_desig_type >= 0 )
      || ( m_code_set >= 0 ) );
  int           k = *off;
  const uint8_t *bp = initial_desig_desc;

  while( ( k + 3 ) < page_len )
  {
    k = ( k < 0 ) ? 0 : ( k + bp[k + 3] + 4 );
    if( ( k + 4 ) > page_len )
      break;
    if( fltr )
    {
      if( m_code_set >= 0 )
      {
        if( ( bp[k] & 0xf ) != m_code_set )
          continue;
      }
      if( m_assoc >= 0 )
      {
        if( ( ( bp[k + 1] >> 4 ) & 0x3 ) != m_assoc )
          continue;
      }
      if( m_desig_type >= 0 )
      {
        if( ( bp[k + 1] & 0xf ) != m_desig_type )
          continue;
      }
    }
    *off = k;
    return 0;
  }
  return ( k == page_len ) ? -1 : -2;
}

/* Add vendor (sg3_utils) specific sense descriptor for the NVMe Status
 * field. Assumes descriptor (i.e. not fixed) sense. Assumes sbp has room. */
void
sg_nvme_desc2sense( uint8_t *sbp, bool dnr, bool more, uint16_t sct_sc )
{
  int           len = sbp[7] + 8;

  sbp[len] = 0xde;              /* vendor specific descriptor type */
  sbp[len + 1] = 6;             /* descriptor is 8 bytes long */
  memset( sbp + len + 2, 0, 6 );
  if( dnr )
    sbp[len + 5] = 0x80;
  if( more )
    sbp[len + 5] |= 0x40;
  sg_put_unaligned_be16( sct_sc, sbp + len + 6 );
  sbp[7] += 8;
}

/* Build minimum sense buffer, either descriptor type (desc=true) or fixed
 * type (desc=false). Assume sbp has enough room (8 or 14 bytes
 * respectively). sbp should have room for 32 or 18 bytes respectively */
void
sg_build_sense_buffer( bool desc, uint8_t *sbp, uint8_t skey, uint8_t asc,
    uint8_t ascq )
{
  if( desc )
  {
    sbp[0] = 0x72;              /* descriptor, current */
    sbp[1] = skey;
    sbp[2] = asc;
    sbp[3] = ascq;
    sbp[7] = 0;
  }
  else
  {
    sbp[0] = 0x70;              /* fixed, current */
    sbp[2] = skey;
    sbp[7] = 0xa;               /* Assumes length is 18 bytes */
    sbp[12] = asc;
    sbp[13] = ascq;
  }
}

/* safe_strerror() contributed by Clayton Weaver <cgweav at email dot com>
 * Allows for situation in which strerror() is given a wild value (or the
 * C library is incomplete) and returns NULL. Still not thread safe.
 */

static char   safe_errbuf[64] = { 'u', 'n', 'k', 'n', 'o', 'w', 'n', ' ',
  'e', 'r', 'r', 'n', 'o', ':', ' ', 0
};

char         *
safe_strerror( int errnum )
{
  size_t        len;
  char         *errstr;

  if( errnum < 0 )
    errnum = -errnum;
  errstr = strerror( errnum );
  if( NULL == errstr )
  {
    len = strlen( safe_errbuf );
    sg_scnpr( safe_errbuf + len, sizeof( safe_errbuf ) - len, "%i", errnum );
    return safe_errbuf;
  }
  return errstr;
}

static void
trimTrailingSpaces( char *b )
{
  int           k;

  for( k = ( ( int ) strlen( b ) - 1 ); k >= 0; --k )
  {
    if( ' ' != b[k] )
      break;
  }
  if( '\0' != b[k + 1] )
    b[k + 1] = '\0';
}

/* Note the ASCII-hex output goes to stdout. [Most other output from functions
 * in this file go to sg_warnings_strm (default stderr).]
 * 'no_ascii' allows for 3 output types:
 *     > 0     each line has address then up to 16 ASCII-hex bytes
 *     = 0     in addition, the bytes are listed in ASCII to the right
 *     < 0     only the ASCII-hex bytes are listed (i.e. without address) */
static void
dStrHexFp( const char *str, int len, int no_ascii, FILE *fp )
{
  const char   *p = str;
  const char   *formatstr;
  uint8_t       c;
  char          buff[82];
  int           a = 0;
  int           bpstart = 5;
  const int     cpstart = 60;
  int           cpos = cpstart;
  int           bpos = bpstart;
  int           i, k, blen;

  if( len <= 0 )
    return;
  blen = ( int ) sizeof( buff );
  if( 0 == no_ascii )           /* address at left and ASCII at right */
    formatstr = "%.76s\n";
  else                          /* previously when > 0 str was "%.58s\n" */
    formatstr = "%s\n";         /* when < 0 str was: "%.48s\n" */
  memset( buff, ' ', 80 );
  buff[80] = '\0';
  if( no_ascii < 0 )
  {
    bpstart = 0;
    bpos = bpstart;
    for( k = 0; k < len; k++ )
    {
      c = *p++;
      if( bpos == ( bpstart + ( 8 * 3 ) ) )
        bpos++;
      sg_scnpr( &buff[bpos], blen - bpos, "%.2x", ( int ) ( uint8_t ) c );
      buff[bpos + 2] = ' ';
      if( ( k > 0 ) && ( 0 == ( ( k + 1 ) % 16 ) ) )
      {
        trimTrailingSpaces( buff );
        fprintf( fp, formatstr, buff );
        bpos = bpstart;
        memset( buff, ' ', 80 );
      }
      else
        bpos += 3;
    }
    if( bpos > bpstart )
    {
      buff[bpos + 2] = '\0';
      trimTrailingSpaces( buff );
      fprintf( fp, "%s\n", buff );
    }
    return;
  }
  /* no_ascii>=0, start each line with address (offset) */
  k = sg_scnpr( buff + 1, blen - 1, "%.2x", a );
  buff[k + 1] = ' ';

  for( i = 0; i < len; i++ )
  {
    c = *p++;
    bpos += 3;
    if( bpos == ( bpstart + ( 9 * 3 ) ) )
      bpos++;
    sg_scnpr( &buff[bpos], blen - bpos, "%.2x", ( int ) ( uint8_t ) c );
    buff[bpos + 2] = ' ';
    if( no_ascii )
      buff[cpos++] = ' ';
    else
    {
      if( !my_isprint( c ) )
        c = '.';
      buff[cpos++] = c;
    }
    if( cpos > ( cpstart + 15 ) )
    {
      if( no_ascii )
        trimTrailingSpaces( buff );
      fprintf( fp, formatstr, buff );
      bpos = bpstart;
      cpos = cpstart;
      a += 16;
      memset( buff, ' ', 80 );
      k = sg_scnpr( buff + 1, blen - 1, "%.2x", a );
      buff[k + 1] = ' ';
    }
  }
  if( cpos > cpstart )
  {
    buff[cpos] = '\0';
    if( no_ascii )
      trimTrailingSpaces( buff );
    fprintf( fp, "%s\n", buff );
  }
}

void
dStrHex( const char *str, int len, int no_ascii )
{
  dStrHexFp( str, len, no_ascii, stdout );
}

void
dStrHexErr( const char *str, int len, int no_ascii )
{
  dStrHexFp( str, len, no_ascii,
      ( sg_warnings_strm ? sg_warnings_strm : stderr ) );
}

#define DSHS_LINE_BLEN 160
#define DSHS_BPL 16

/* Read 'len' bytes from 'str' and output as ASCII-Hex bytes (space
 * separated) to 'b' not to exceed 'b_len' characters. Each line
 * starts with 'leadin' (NULL for no leadin) and there are 16 bytes
 * per line with an extra space between the 8th and 9th bytes. 'format'
 * is 0 for repeat in printable ASCII ('.' for non printable) to
 * right of each line; 1 don't (so just output ASCII hex). Returns
 * number of bytes written to 'b' excluding the trailing '\0'. */
int
dStrHexStr( const char *str, int len, const char *leadin, int format,
    int b_len, char *b )
{
  uint8_t       c;
  int           bpstart, bpos, k, n, prior_ascii_len;
  bool          want_ascii;
  char          buff[DSHS_LINE_BLEN + 2];
  char          a[DSHS_BPL + 1];
  const char   *p = str;

  if( len <= 0 )
  {
    if( b_len > 0 )
      b[0] = '\0';
    return 0;
  }
  if( b_len <= 0 )
    return 0;
  want_ascii = !format;
  if( want_ascii )
  {
    memset( a, ' ', DSHS_BPL );
    a[DSHS_BPL] = '\0';
  }
  if( leadin )
  {
    bpstart = strlen( leadin );
    /* Cap leadin at (DSHS_LINE_BLEN - 70) characters */
    if( bpstart > ( DSHS_LINE_BLEN - 70 ) )
      bpstart = DSHS_LINE_BLEN - 70;
  }
  else
    bpstart = 0;
  bpos = bpstart;
  prior_ascii_len = bpstart + ( DSHS_BPL * 3 ) + 1;
  n = 0;
  memset( buff, ' ', DSHS_LINE_BLEN );
  buff[DSHS_LINE_BLEN] = '\0';
  if( bpstart > 0 )
    memcpy( buff, leadin, bpstart );
  for( k = 0; k < len; k++ )
  {
    c = *p++;
    if( bpos == ( bpstart + ( ( DSHS_BPL / 2 ) * 3 ) ) )
      bpos++;                   /* for extra space in middle of each line's hex */
    sg_scnpr( buff + bpos, ( int ) sizeof( buff ) - bpos, "%.2x",
        ( int ) ( uint8_t ) c );
    buff[bpos + 2] = ' ';
    if( want_ascii )
      a[k % DSHS_BPL] = my_isprint( c ) ? c : '.';
    if( ( k > 0 ) && ( 0 == ( ( k + 1 ) % DSHS_BPL ) ) )
    {
      trimTrailingSpaces( buff );
      if( want_ascii )
      {
        n += sg_scnpr( b + n, b_len - n, "%-*s	%s\n",
            prior_ascii_len, buff, a );
        memset( a, ' ', DSHS_BPL );
      }
      else
        n += sg_scnpr( b + n, b_len - n, "%s\n", buff );
      if( n >= ( b_len - 1 ) )
        return n;
      memset( buff, ' ', DSHS_LINE_BLEN );
      bpos = bpstart;
      if( bpstart > 0 )
        memcpy( buff, leadin, bpstart );
    }
    else
      bpos += 3;
  }
  if( bpos > bpstart )
  {
    trimTrailingSpaces( buff );
    if( want_ascii )
      n += sg_scnpr( b + n, b_len - n, "%-*s   %s\n", prior_ascii_len,
          buff, a );
    else
      n += sg_scnpr( b + n, b_len - n, "%s\n", buff );
  }
  return n;
}

void
hex2stdout( const uint8_t *b_str, int len, int no_ascii )
{
  dStrHex( ( const char * ) b_str, len, no_ascii );
}

void
hex2stderr( const uint8_t *b_str, int len, int no_ascii )
{
  dStrHexErr( ( const char * ) b_str, len, no_ascii );
}

int
hex2str( const uint8_t *b_str, int len, const char *leadin, int format,
    int b_len, char *b )
{
  return dStrHexStr( ( const char * ) b_str, len, leadin, format, b_len, b );
}

/* Returns true when executed on big endian machine; else returns false.
 * Useful for displaying ATA identify words (which need swapping on a
 * big endian machine). */
bool
sg_is_big_endian(  )
{
  union u_t
  {
    uint16_t      s;
    uint8_t       c[sizeof( uint16_t )];
  }
  u;

  u.s = 0x0102;
  return ( u.c[0] == 0x01 );    /* The lowest address contains the most significant byte */
}

bool
sg_all_zeros( const uint8_t *bp, int b_len )
{
  if( ( NULL == bp ) || ( b_len <= 0 ) )
    return false;
  for( --b_len; b_len >= 0; --b_len )
  {
    if( 0x0 != bp[b_len] )
      return false;
  }
  return true;
}

bool
sg_all_ffs( const uint8_t *bp, int b_len )
{
  if( ( NULL == bp ) || ( b_len <= 0 ) )
    return false;
  for( --b_len; b_len >= 0; --b_len )
  {
    if( 0xff != bp[b_len] )
      return false;
  }
  return true;
}

/* If the number in 'buf' can not be decoded or the multiplier is unknown
 * then -1 is returned. Accepts a hex prefix (0x or 0X) or a decimal
 * multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
 * Main (SI) multipliers supported: K, M, G. Ignore leading spaces and
 * tabs; accept comma, hyphen, space, tab and hash as terminator.
 * Handles zero and positive values up to 2**31-1 .
 * Experimental: left argument (must in with hexadecimal digit) added
 * to, or multiplied, by right argument. No embedded spaces.
 * Examples: '3+1k' (evaluates to 1027) and '0x34+1m'. */
int
sg_get_num( const char *buf )
{
  bool          is_hex = false;
  int           res, num, n, len;
  unsigned int  unum;
  char         *cp;
  const char   *b;
  const char   *b2p;
  char          c = 'c';
  char          c2 = '\0';      /* keep static checker happy */
  char          c3 = '\0';      /* keep static checker happy */
  char          lb[16];

  if( ( NULL == buf ) || ( '\0' == buf[0] ) )
    return -1;
  len = strlen( buf );
  n = strspn( buf, " \t" );
  if( n > 0 )
  {
    if( n == len )
      return -1;
    buf += n;
    len -= n;
  }
  /* following hack to keep C++ happy */
  cp = strpbrk( ( char * ) buf, " \t,#-" );
  if( cp )
  {
    len = cp - buf;
    n = ( int ) sizeof( lb ) - 1;
    len = ( len < n ) ? len : n;
    memcpy( lb, buf, len );
    lb[len] = '\0';
    b = lb;
  }
  else
    b = buf;

  b2p = b;
  if( ( '0' == b[0] ) && ( ( 'x' == b[1] ) || ( 'X' == b[1] ) ) )
  {
    res = sscanf( b + 2, "%x%c", &unum, &c );
    num = unum;
    is_hex = true;
    b2p = b + 2;
  }
  else if( 'H' == toupper( ( int ) b[len - 1] ) )
  {
    res = sscanf( b, "%x", &unum );
    num = unum;
  }
  else
    res = sscanf( b, "%d%c%c%c", &num, &c, &c2, &c3 );

  if( res < 1 )
    return -1;
  else if( 1 == res )
    return num;
  else
  {
    c = toupper( ( int ) c );
    if( is_hex )
    {
      if( !( ( c == '+' ) || ( c == 'X' ) ) )
        return -1;
    }
    if( res > 2 )
      c2 = toupper( ( int ) c2 );
    if( res > 3 )
      c3 = toupper( ( int ) c3 );

    switch ( c )
    {
      case 'C':
        return num;
      case 'W':
        return num * 2;
      case 'B':
        return num * 512;
      case 'K':
        if( 2 == res )
          return num * 1024;
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000;
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1024;
        return -1;
      case 'M':
        if( 2 == res )
          return num * 1048576;
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000;
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1048576;
        return -1;
      case 'G':
        if( 2 == res )
          return num * 1073741824;
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000000;
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1073741824;
        return -1;
      case 'X':                /* experimental: multiplication */
        /* left argument must end with hexadecimal digit */
        cp = ( char * ) strchr( b2p, 'x' );
        if( NULL == cp )
          cp = ( char * ) strchr( b2p, 'X' );
        if( cp )
        {
          n = sg_get_num( cp + 1 );
          if( -1 != n )
            return num * n;
        }
        return -1;
      case '+':                /* experimental: addition */
        /* left argument must end with hexadecimal digit */
        cp = ( char * ) strchr( b2p, '+' );
        if( cp )
        {
          n = sg_get_num( cp + 1 );
          if( -1 != n )
            return num + n;
        }
        return -1;
      default:
        pr2ws( "unrecognized multiplier\n" );
        return -1;
    }
  }
}

/* If the number in 'buf' can not be decoded or the multiplier is unknown
 * then -1LL is returned. Accepts a hex prefix (0x or 0X), hex suffix
 * (h or H), or a decimal multiplier suffix (as per GNU's dd (since 2002:
 * SI and IEC 60027-2)).  Main (SI) multipliers supported: K, M, G, T, P
 * and E. Ignore leading spaces and tabs; accept comma, hyphen, space, tab
 * and hash as terminator. Handles zero and positive values up to 2**63-1 .
 * Experimental: left argument (must in with hexadecimal digit) added
 * to, or multiplied by right argument. No embedded spaces.
 * Examples: '3+1k' (evaluates to 1027) and '0x34+1m'. */
int64_t
sg_get_llnum( const char *buf )
{
  bool          is_hex = false;
  int           res, len, n;
  int64_t       num, ll;
  uint64_t      unum;
  char         *cp;
  const char   *b;
  const char   *b2p;
  char          c = 'c';
  char          c2 = '\0';      /* keep static checker happy */
  char          c3 = '\0';      /* keep static checker happy */
  char          lb[32];

  if( ( NULL == buf ) || ( '\0' == buf[0] ) )
    return -1LL;
  len = strlen( buf );
  n = strspn( buf, " \t" );
  if( n > 0 )
  {
    if( n == len )
      return -1LL;
    buf += n;
    len -= n;
  }
  /* following hack to keep C++ happy */
  cp = strpbrk( ( char * ) buf, " \t,#-" );
  if( cp )
  {
    len = cp - buf;
    n = ( int ) sizeof( lb ) - 1;
    len = ( len < n ) ? len : n;
    memcpy( lb, buf, len );
    lb[len] = '\0';
    b = lb;
  }
  else
    b = buf;

  b2p = b;
  if( ( '0' == b[0] ) && ( ( 'x' == b[1] ) || ( 'X' == b[1] ) ) )
  {
    res = sscanf( b + 2, "%" SCNx64 "%c", &unum, &c );
    num = unum;
    is_hex = true;
    b2p = b + 2;
  }
  else if( 'H' == toupper( ( int ) b[len - 1] ) )
  {
    res = sscanf( b, "%" SCNx64, &unum );
    num = unum;
  }
  else
    res = sscanf( b, "%" SCNd64 "%c%c%c", &num, &c, &c2, &c3 );

  if( res < 1 )
    return -1LL;
  else if( 1 == res )
    return num;
  else
  {
    c = toupper( ( int ) c );
    if( is_hex )
    {
      if( !( ( c == '+' ) || ( c == 'X' ) ) )
        return -1;
    }
    if( res > 2 )
      c2 = toupper( ( int ) c2 );
    if( res > 3 )
      c3 = toupper( ( int ) c3 );

    switch ( c )
    {
      case 'C':
        return num;
      case 'W':
        return num * 2;
      case 'B':
        return num * 512;
      case 'K':                /* kilo or kibi */
        if( 2 == res )
          return num * 1024;
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000;
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1024;    /* KiB */
        return -1LL;
      case 'M':                /* mega or mebi */
        if( 2 == res )
          return num * 1048576; /* M */
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000; /* MB */
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1048576; /* MiB */
        return -1LL;
      case 'G':                /* giga or gibi */
        if( 2 == res )
          return num * 1073741824;      /* G */
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000000;      /* GB */
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1073741824;      /* GiB */
        return -1LL;
      case 'T':                /* tera or tebi */
        if( 2 == res )
          return num * 1099511627776LL; /* T */
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000000000LL; /* TB */
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1099511627776LL; /* TiB */
        return -1LL;
      case 'P':                /* peta or pebi */
        if( 2 == res )
          return num * 1099511627776LL * 1024;
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000000000LL * 1000;
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1099511627776LL * 1024;
        return -1LL;
      case 'E':                /* exa or exbi */
        if( 2 == res )
          return num * 1099511627776LL * 1024 * 1024;
        if( ( 'B' == c2 ) || ( 'D' == c2 ) )
          return num * 1000000000000LL * 1000 * 1000;
        if( ( 'I' == c2 ) && ( 4 == res ) && ( 'B' == c3 ) )
          return num * 1099511627776LL * 1024 * 1024;
        return -1LL;
      case 'X':                /* experimental: decimal (left arg) multiplication */
        cp = ( char * ) strchr( b2p, 'x' );
        if( NULL == cp )
          cp = ( char * ) strchr( b2p, 'X' );
        if( cp )
        {
          ll = sg_get_llnum( cp + 1 );
          if( -1LL != ll )
            return num * ll;
        }
        return -1LL;
      case '+':                /* experimental: decimal (left arg) addition */
        cp = ( char * ) strchr( b2p, '+' );
        if( cp )
        {
          ll = sg_get_llnum( cp + 1 );
          if( -1LL != ll )
            return num + ll;
        }
        return -1LL;
      default:
        pr2ws( "unrecognized multiplier\n" );
        return -1LL;
    }
  }
}

uint32_t
sg_get_page_size( void )
{
#ifdef _SC_PAGESIZE
  return sysconf( _SC_PAGESIZE );       /* POSIX.1 (was getpagesize()) */
#else
  return 4096;                  /* give up, pick likely figure */
#endif
}

/* Returns pointer to heap (or NULL) that is aligned to a align_to byte
 * boundary. Sends back *buff_to_free pointer in third argument that may be
 * different from the return value. If it is different then the *buff_to_free
 * pointer should be freed (rather than the returned value) when the heap is
 * no longer needed. If align_to is 0 then aligns to OS's page size. Sets all
 * returned heap to zeros. If num_bytes is 0 then set to page size. */
uint8_t      *
sg_memalign( uint32_t num_bytes, uint32_t align_to, uint8_t **buff_to_free,
    bool vb )
{
  size_t        psz;
  uint8_t      *res;
  int           err;
  void         *wp = NULL;

  if( buff_to_free )            /* make sure buff_to_free is NULL if alloc fails */
    *buff_to_free = NULL;
  psz = ( align_to > 0 ) ? align_to : sg_get_page_size(  );
  if( 0 == num_bytes )
    num_bytes = psz;            /* ugly to handle otherwise */
  err = posix_memalign( &wp, psz, num_bytes );
  if( err || ( NULL == wp ) )
  {
    pr2ws( "%s: posix_memalign: error [%d], out of memory?\n",
        __func__, err );
    return NULL;
  }
  memset( wp, 0, num_bytes );
  if( buff_to_free )
    *buff_to_free = ( uint8_t * ) wp;
  res = ( uint8_t * ) wp;
  if( vb )
  {
    pr2ws( "%s: posix_ma, len=%d, ", __func__, num_bytes );
    if( buff_to_free )
      pr2ws( "wrkBuffp=%p, ", ( void * ) res );
    pr2ws( "psz=%u, rp=%p\n", ( unsigned int ) psz, ( void * ) res );
  }
  return res;
}

