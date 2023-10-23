#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <bsd/readpassphrase.h>
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_pt_linux.h"
#include "sg_pr2serr.h"
#include "sg_unaligned.h"

enum pass_xchg
{ CHANGE_PASSWD, SET_PASSWD, DISABLE_ENCRYPTION = 16 };

#define WD_READ_HANDY_STORE(x) {x[0] = 0xD8, x[1] = 0; memset( x+2, 0, 8 );}
#define WD_WRITE_HANDY_STORE(x) {x[0] = 0xDA, x[1] = 0; memset( x+2, 0, 8 );}
#define WD_GET_ENCRYPTION_STATUS(x) {x[0] = 0xC0, x[1] = 0x45; memset( x+2, 0, 8 );}
#define WD_UNLOCK(x) {x[0] = 0xC1, x[1] = 0xE1; memset( x+2, 0, 8 );}
#define WD_CHANGE_PASSWORD(x) {x[0] = 0xC1, x[1] = 0xE2; memset( x+2, 0, 8 );}
#define WD_SECURE_ERASE(x) {x[0] = 0xC1, x[1] = 0xE3; memset( x+2, 0, 8 );}

struct switches
{
  unsigned int  verbose:3;
  unsigned int  status:1;
  unsigned int  getlabel:1;
  unsigned int  setlabel:1;
  unsigned int  gethint:1;
  unsigned int  sethint:1;
  unsigned int  unlock:1;
  unsigned int  newsalt:1;
  unsigned int  newpasswd:1;
  unsigned int  changepasswd:1;
  unsigned int  disableencryption:1;
  unsigned int  erase:1;
} sw;

char         *find_passport_device( void );
void          sha256hash( const uint8_t * data, unsigned int len,
    uint8_t * out );

static struct option long_options[] = {
  {"help", no_argument, 0, 'h'},
  {"verbose", no_argument, 0, 'v'},
  {"status", no_argument, 0, 's'},
  {"unlock", no_argument, 0, 'u'},
  {"get_disk_label", no_argument, 0, 'l'},
  {"set_disk_label", no_argument, 0, 'L'},
  {"get_passwd_hint", no_argument, 0, 'i'},
  {"set_passwd_hint", no_argument, 0, 'I'},
  {"set_new_salt", no_argument, 0, 'S'},
  {"set_new_passwd", no_argument, 0, 'P'},
  {"change_passwd", no_argument, 0, 'C'},
  {"disable_encryption", no_argument, 0, 'D'},
  {"erase_reset_key", no_argument, 0, 'E'},
  {0, 0, 0, 0}
};

static struct opt_help
{
  uint8_t       opt;
  char         *help;
} options_help[] = {
  {'s', "print disk's security/encryption status"},
  {'u', "unlock the drive encryption key (requires current password)"},
  {'l', "print disk's label (stored in handy block 2)"},
  {'L', "set new disk label"},
  {'i', "print password hint (stored in handy block 1)"},
  {'I', "set new password hint"},
  {'S', "generate and store new seed\n"
    "\t\t\t    (which is used to generate the disk's encryption key)"},
  {'P', "set a new password (disk's encryption must be disabled"},
  {'C', "change the current password (disk must be previously unlocked)"},
  {'D', "disable disk's encryption (removes user key)"},
  {'E', "emergency key reset (all disk content is lost as a result)"},
  {0, ""}
};

static void
usage(  )
{
  struct option *o = long_options;
  struct opt_help *h;

  pr2serr( "Usage: wd_passport [options]\n" );
  while( o->name )
  {
    for( h = options_help; h->opt; h++ )
    {
      if( o->val == h->opt )
	break;
    }
    pr2serr( "  -%c,--%-20s %s\n", o->val, o->name, h->help );
    o++;
  }
  exit( 0 );
}

static int
parse_cmd_line( int argc, char *argv[] )
{
  int           idx = 0;
  int          *allsw = ( int * ) &sw;
  int           c;

  while( 1 )
  {
    c = getopt_long( argc, argv, "hvsulLiISPCDE", long_options, &idx );
    if( c == -1 )
      break;
    switch ( c )
    {
      case 'h':
      case '?':
	usage(  );
      case 'v':
	sw.verbose++;
	break;
      case 's':
	sw.status = 1;
	break;
      case 'u':
	sw.unlock = 1;
	break;
      case 'l':
	sw.getlabel = 1;
	break;
      case 'L':
	sw.setlabel = 1;
	break;
      case 'i':
	sw.gethint = 1;
	break;
      case 'I':
	sw.sethint = 1;
	break;
      case 'S':
	sw.newsalt = 1;
	break;
      case 'P':
	sw.newpasswd = 1;
	break;
      case 'C':
	sw.changepasswd = 1;
	break;
      case 'D':
	sw.disableencryption = 1;
	break;
      case 'E':
	sw.erase = 1;
	break;
    }
  }
  if( 0 == ( *allsw >> 3 ) )
    usage(  );
  return 0;
}

// Convert an integer to his human-readable secure status
char         *
sec_status_to_str( int security_status )
{
  switch ( security_status )
  {
    case 0x00:
      return "No lock";
    case 0x01:
      return "Locked";
    case 0x02:
      return "Unlocked";
    case 0x06:
      return "Locked, unlock blocked";
    case 0x07:
      return "No keys";
    default:
      return "unknown";
  }
}

// Convert an integer to his human-readable cipher algorithm
char         *
cipher_id_to_str( int cipher_id )
{
  static char   result[16];

  switch ( cipher_id )
  {
    case 0x10:
      return "AES_128_ECB";
    case 0x12:
      return "AES_128_CBC";
    case 0x18:
      return "AES_128_XTS";
    case 0x20:
      return "AES_256_ECB";
    case 0x22:
      return "AES_256_CBC";
    case 0x28:
      return "AES_256_XTS";
    case 0x30:
      return "Full Disk Encryption";
    default:
      sprintf( result, "Unknown (%02X)", cipher_id );
      return result;
  }
}

int
secure_erase_drive( struct scsi_op_t *op )
{
  int           pwblen, key_reset_enabler;
  int           frnd = open( "/dev/urandom", O_RDONLY );

  if( frnd < 0 )
    return 0;
  WD_SECURE_ERASE( cdb );
  key_reset_enabler = sg_get_unaligned_be32( &reply[8] );
  sg_put_unaligned_be32( key_reset_enabler, &cdb[2] );	// Key Reset Enabler
  memset( cmdout, 0, MAX_SCSI_XFER );
  cmdout[0] = 0x45;
  cmdout[4] = reply[4];		// Cipher ID
  pwblen = sg_get_unaligned_be16( &reply[6] );	// Password Length
  if( pwblen < 16 || pwblen > 32 )
    pwblen = 32;
  sg_put_unaligned_be16( 8 + pwblen, &cdb[7] );
  read( frnd, &cmdout[8], pwblen );
  close( frnd );
  op->dir_inout = true;
  op->data_len = 8 + pwblen;
  return !scsi_xfer( op );
}

static int
read_handy_store( struct scsi_op_t *op, int page )
{
  WD_READ_HANDY_STORE( cdb );
  sg_put_unaligned_be32( page, &cdb[2] );
  sg_put_unaligned_be16( 1, &cdb[7] );
  op->dir_inout = false;
  op->data_len = MAX_SCSI_XFER;
  return !scsi_xfer( op );
}

static char  *
read_handy_store_block1( struct scsi_op_t *op )
{
  int           i;
  uint8_t       sum;
  static char   hint[102];

  if( !read_handy_store( op, 1 ) )
    return NULL;
  if( reply[0] != 0 || reply[1] != 1 || reply[2] != 'W' || reply[3] != 'D' )
    return NULL;
  for( sum = i = 0; i < MAX_SCSI_XFER; i++ )
    sum += reply[i];
  if( sum != 0 )
    return NULL;
  for( i = 0; i < 101; i++ )
  {
    hint[i] = reply[24 + 2 * i];
    if( !hint[i] )
      break;
  }
  hint[i] = 0;
  return hint;
}

static char  *
read_handy_store_block2( struct scsi_op_t *op )
{
  int           i;
  uint8_t       sum;
  static char   label[33];

  if( !read_handy_store( op, 2 ) )
    return NULL;
  if( reply[0] != 0 || reply[1] != 2 || reply[2] != 'W' || reply[3] != 'D' )
    return NULL;
  for( sum = i = 0; i < MAX_SCSI_XFER; i++ )
    sum += reply[i];
  if( sum != 0 )
    return NULL;
  for( i = 0; i < 32; i++ )
  {
    label[i] = reply[8 + 2 * i];
    if( !label[i] )
      break;
  }
  label[i] = 0;
  return label;
}

static int
write_handy_store( struct scsi_op_t *op, int page )
{
  WD_WRITE_HANDY_STORE( cdb );
  sg_put_unaligned_be32( page, &cdb[2] );
  sg_put_unaligned_be16( 1, &cdb[7] );
  op->dir_inout = true;
  op->data_len = MAX_SCSI_XFER;
  return !scsi_xfer( op );
}

static int
write_handy_store_block1( struct scsi_op_t *op, int new_salt, char *hint )
{
  char         *old_hint;
  uint8_t       sum, c;
  int           frnd = open( "/dev/urandom", O_RDONLY );
  int           i;

  old_hint = read_handy_store_block1( op );
  memset( cmdout, 0, MAX_SCSI_XFER );
  cmdout[1] = 1;
  cmdout[2] = 'W';
  cmdout[3] = 'D';
  if( new_salt || old_hint == NULL )
  {
    read( frnd, &cmdout[11], 9 );
    cmdout[11] &= 7;
    cmdout[11]++;		// between 1-8 hash iterations
    for( i = 0; i < 4; i++ )	// force SALT as UCS-2 chars
    {
      c = cmdout[12 + 2 * i] & 0x7f;
      if( c < '#' )
	c += '#';
      if( c > 'z' )
	c -= 5;
      cmdout[12 + 2 * i] = c;
      cmdout[13 + 2 * i] = 0;
    }
  }
  else				// preserve iterations and salt
  {
    memcpy( &cmdout[8], &reply[8], 12 );
  }
  close( frnd );
  if( hint )
  {
    for( i = 0; i < 101; i++ )
    {
      cmdout[24 + 2 * i] = hint[i];
      if( !hint[i] )
	break;
    }
  }
  else if( old_hint )
  {
    for( i = 0; i < 101; i++ )
    {
      cmdout[24 + 2 * i] = old_hint[i];
      if( !old_hint[i] )
	break;
    }
    old_hint[i] = 0;
  }
  for( sum = i = 0; i < MAX_SCSI_XFER; i++ )
    sum += cmdout[i];
  cmdout[MAX_SCSI_XFER - 1] = -sum;
  if( write_handy_store( op, 1 ) )
    return 1;
  return 0;
}

static int
write_handy_store_block2( struct scsi_op_t *op, char *label )
{
  int           i;
  uint8_t       sum;

  memset( cmdout, 0, MAX_SCSI_XFER );
  cmdout[1] = 2;
  cmdout[2] = 'W';
  cmdout[3] = 'D';
  for( i = 0; i < 32; i++ )
  {
    if( label[i] < ' ' )
      break;
    cmdout[8 + 2 * i] = label[i];
  }
  for( sum = i = 0; i < MAX_SCSI_XFER; i++ )
    sum += cmdout[i];
  cmdout[MAX_SCSI_XFER - 1] = -sum;
  if( write_handy_store( op, 2 ) )
    return 1;
  return 0;
}

static uint8_t *
hash_password( char *salt, char *password, int iterations )
{
  static uint8_t digest[32];
  uint8_t       salt_passwd[138];
  int           i, len;

  memset( salt_passwd, 0, 138 );
  memcpy( salt_passwd, &reply[12], 8 );	// UCS-2 salt
  for( i = 0; i < 64; i++ )
  {
    if( password[i] < ' ' )
      break;
    salt_passwd[8 + 2 * i] = password[i];
  }
  len = 8 + 2 * i;
  for( i = 0; i < iterations; i++ )
  {
    sha256hash( salt_passwd, len, digest );
    len = 32;
    memcpy( salt_passwd, digest, len );
  }
  return digest;
}

int
change_password( struct scsi_op_t *op, int security )
{
  int           i, iterations, pwblen;
  char          salt[5], old_passwd[65], new_passwd[65], sec_passwd[65];

  if( security == SET_PASSWD && reply[3] != 0 )
  {
    printf( "Device has to be unprotected to perform this operation.\n" );
    return 0;
  }
  if( ( security == CHANGE_PASSWD || security == DISABLE_ENCRYPTION ) &&
      reply[3] != 2 )
  {
    printf( "Device has to be unlocked to perform this operation.\n" );
    return 0;
  }
  pwblen = sg_get_unaligned_be16( &reply[6] );	// Password Length
  if( read_handy_store_block1( op ) == NULL )
  {
    printf( "!!! WARNING !!!\n"
	"If this is the first time you set a password,\n"
	"make sure you change it at least once.\n"
	"Otherwise the factory password can be used to\n"
	"decrypt your data!!!\n" );
    write_handy_store_block1( op, 1, NULL );
  }
  iterations = sg_get_unaligned_be32( &reply[8] );
  for( i = 0; i < 4; i++ )	// UCS-2 salt
    salt[i] = reply[12 + 2 * i];
  salt[i] = 0;
  WD_CHANGE_PASSWORD( cdb );
  sg_put_unaligned_be16( 8 + 2 * pwblen, &cdb[7] );
  memset( cmdout, 0, MAX_SCSI_XFER );
  cmdout[0] = 0x45;
  cmdout[3] = security;
  sg_put_unaligned_be16( pwblen, &cmdout[6] );
  if( security == CHANGE_PASSWD || security == DISABLE_ENCRYPTION )
  {
    if( NULL == readpassphrase( "Please enter current disk password: ",
	old_passwd, 65, RPP_ECHO_OFF ) )
      return 0;
    memcpy( &cmdout[8], hash_password( salt, old_passwd, iterations ),
	pwblen );
  }
  if( security == CHANGE_PASSWD || security == SET_PASSWD )
  {
    if( NULL == readpassphrase( "Please enter new disk password: ",
	new_passwd, 65, RPP_ECHO_OFF ) )
      return 0;
    if( NULL == readpassphrase( "Retype new disk password: ",
	sec_passwd, 65, RPP_ECHO_OFF ) )
      return 0;
    if( strcmp( new_passwd, sec_passwd ) )
    {
      printf( "Passwords don't match\n" );
      return 0;
    }
    memcpy( &cmdout[8 + pwblen],
	hash_password( salt, new_passwd, iterations ), pwblen );
  }
  op->dir_inout = true;
  op->data_len = 8 + 2 * pwblen;
  return !scsi_xfer( op );
}

int
unlock_drive( struct scsi_op_t *op )
{
  int           i, iterations, pwblen;
  char          salt[5], old_passwd[65];

  if( reply[3] != 1 )
  {
    printf( "Drive is not locked.\n" );
    return 0;
  }
  pwblen = sg_get_unaligned_be16( &reply[6] );	// Password Length
  if( read_handy_store_block1( op ) == NULL )
    return 0;
  iterations = sg_get_unaligned_be32( &reply[8] );
  for( i = 0; i < 4; i++ )	// UCS-2 salt
    salt[i] = reply[12 + 2 * i];
  salt[i] = 0;
  WD_UNLOCK( cdb );
  sg_put_unaligned_be16( 8 + pwblen, &cdb[7] );
  memset( cmdout, 0, MAX_SCSI_XFER );
  cmdout[0] = 0x45;
  sg_put_unaligned_be16( pwblen, &cmdout[6] );
  if( NULL == readpassphrase( "Please enter current disk password: ",
      old_passwd, 65, RPP_ECHO_OFF ) )
    return 0;
  memcpy( &cmdout[8], hash_password( salt, old_passwd, iterations ), pwblen );
  op->dir_inout = true;
  op->data_len = 8 + pwblen;
  return !scsi_xfer( op );
}

int
get_encryption_status( struct scsi_op_t *op )
{
  WD_GET_ENCRYPTION_STATUS( cdb );
  sg_put_unaligned_be16( 48, &cdb[7] );
  op->dir_inout = false;
  op->data_len = MAX_SCSI_XFER;
  if( !scsi_xfer( op ) && reply[0] == 0x45 )
    return 1;
  return 0;
}

int
main( int argc, char *argv[] )
{
  struct scsi_op_t opts, *op = &opts;
  char          set_label[33], *get_label;
  char          set_hint[102], *get_hint;
  int           c;

  parse_cmd_line( argc, argv );
  memset( op, 0, sizeof( opts ) );
  if( ( op->device_name = find_passport_device(  ) ) == NULL )
  {
    printf( "No WD Passport device found.\n" );
    return -1;
  }
  printf( "WD Passport device: %s\n", op->device_name );
  if( !get_encryption_status( op ) )
  {
    printf( "Cannot get encryption status.\n" );
    return -1;
  }
  if( sw.status )
  {
    printf( "Security: %s\n", sec_status_to_str( reply[3] ) );
    printf( "Cipher: %s\n", cipher_id_to_str( reply[4] ) );
  }
  if( sw.unlock )
  {
    if( unlock_drive( op ) )
      printf( "Drive unlocked successfully.\n" );
    else
      printf( "Error unlocking drive.\n" );
    return 0;
  }
  if( sw.getlabel )
  {
    get_label = read_handy_store_block2( op );
    if( get_label )
      printf( "Disk label: %s\n", get_label );
    else
      printf( "Disk label was not yet set\n" );
    return 0;
  }
  if( sw.setlabel )
  {
    if( NULL == readpassphrase( "Please enter new disk label: ",
	set_label, 33, RPP_ECHO_ON ) )
      return 0;
    if( write_handy_store_block2( op, set_label ) )
    {
      printf( "Disk label was set\n" );
      return 1;
    }
    return 0;
  }
  if( sw.gethint )
  {
    get_hint = read_handy_store_block1( op );
    if( get_hint )
      printf( "Password hint: %s\n", get_hint );
    else
      printf( "Password hint was not yet set\n" );
    return 0;
  }
  if( sw.sethint )
  {
    if( NULL == readpassphrase( "Please enter a password hint: ",
	set_hint, 102, RPP_ECHO_ON ) )
      return 0;
    if( write_handy_store_block1( op, 0, set_hint ) )
    {
      printf( "Password hint was set\n" );
      return 1;
    }
    return 0;
  }
  if( sw.newsalt )
  {
    if( reply[3] != 0 )
    {
      printf( "Device has to be unprotected to perform this operation.\n" );
      return 0;
    }
    if( write_handy_store_block1( op, 1, NULL ) )
    {
      printf( "Generating and storing new salt.\n" );
      return 1;
    }
    return 0;
  }
  if( sw.newpasswd )
  {
    if( change_password( op, SET_PASSWD ) )
      printf( "Password was set successfully.\n" );
    else
      printf( "Error setting new password.\n" );
    return 0;
  }
  if( sw.changepasswd )
  {
    if( change_password( op, CHANGE_PASSWD ) )
      printf( "Password changed successfully.\n" );
    else
      printf( "Error changing password.\n" );
    return 0;
  }
  if( sw.disableencryption )
  {
    if( change_password( op, DISABLE_ENCRYPTION ) )
      printf( "Security is disabled (no password).\n" );
    else
      printf( "Security disabled operation failed.\n" );
    return 0;
  }
  if( sw.erase )
  {
    printf( "!!! All data on %s will be lost !!!\n", op->device_name );
    printf( "Are you sure you want to continue? [y/N] " );
    fflush( stdout );
    c = getchar(  );
    c |= 0x20;
    if( c == 'y' )
    {
      if( secure_erase_drive( op ) )
	printf
	    ( "Device erased. You need to create a new partition on the device.\n" );
      else
	printf( "Something went wrong.\n" );
    }
    else
      printf( "Ok, nevermind.\n" );
    return 0;
  }
  return 0;
}
