#define _XOPEN_SOURCE 600
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "sg_unaligned.h"

#define FT_OTHER 0
#define FT_BLOCK 1
#define FT_CHAR 2

#ifdef PATH_MAX
#define LMAX_PATH PATH_MAX
#else
#define LMAX_PATH 2048
#endif

#ifdef NAME_MAX
#define LMAX_NAME (NAME_MAX + 1)
#else
#define LMAX_NAME 256
#endif

#define LMAX_DEVPATH (LMAX_NAME + 128)

#define UINT64_LAST ((uint64_t)~0)

static const char *sysfsroot = "/sys";
static const char *bus_scsi_devs = "/bus/scsi/devices";
static const char *dev_dir = "/dev";

/* For SCSI 'h' is host_num, 'c' is channel, 't' is target, 'l' is LUN is
 * uint64_t and lun_arr[8] is LUN as 8 byte array. For NVMe, h=0x7fff
 * (NVME_HOST_NUM) and displayed as 'N'; 'c' is Linux's NVMe controller
 * number, 't' is NVMe Identify controller CTNLID field, and 'l' is
 * namespace id (1 to (2**32)-1) rendered as a little endian 4 byte sequence
 * in lun_arr, last 4 bytes are zero */
struct addr_hctl
{
  int           h;              /* if h==0x7fff, display as 'N' for NVMe */
  int           c;
  int           t;
  uint64_t      l;              /* SCSI: Linux word flipped; NVME: uint32_t */
  uint8_t       lun_arr[8];     /* T10, SAM-5 order; NVME: little endian */
};

struct addr_hctl filter;

/* Device node list: contains the information needed to match a node with a
 * sysfs class device. */
#define DEV_NODE_LIST_ENTRIES 16
enum dev_type
{ BLK_DEV, CHR_DEV };

struct dev_node_entry
{
  unsigned int  maj, min;
  enum dev_type type;
  time_t        mtime;
  char          name[LMAX_DEVPATH];
};

struct dev_node_list
{
  struct dev_node_list *next;
  unsigned int  count;
  struct dev_node_entry nodes[DEV_NODE_LIST_ENTRIES];
};
static struct dev_node_list *dev_node_listhead = NULL;

struct item_t
{
  char          name[LMAX_NAME];
  int           ft;
  int           d_type;
};

static struct item_t non_sg;
static struct item_t aa_first;

/* Returns true if dirent entry is either a symlink or a directory
 * starting_with given name. If starting_with is NULL choose all that are
 * either symlinks or directories other than . or .. (own directory or
 * parent) . Can be tricked cause symlink could point to .. (parent), for
 * example. Otherwise return false. */
static bool
dir_or_link( const struct dirent *s, const char *starting_with )
{
  if( DT_LNK == s->d_type )
  {
    if( starting_with )
      return 0 == strncmp( s->d_name, starting_with,
          strlen( starting_with ) );
    return true;
  }
  else if( DT_DIR != s->d_type )
    return false;
  else
  {                             /* Assume can't have zero length directory name */
    size_t        len = strlen( s->d_name );

    if( starting_with )
      return 0 == strncmp( s->d_name, starting_with,
          strlen( starting_with ) );
    if( len > 2 )
      return true;
    if( '.' == s->d_name[0] )
    {
      if( 1 == len )
        return false;           /* this directory: '.' */
      else if( '.' == s->d_name[1] )
        return false;           /* parent: '..' */
    }
    return true;
  }
}

enum string_size_units
{
  STRING_UNITS_10 = 0,          /* use powers of 10^3 (standard SI) */
  STRING_UNITS_2,               /* use binary powers of 2^10 */
};

/* Return 1 for directory entry that is link or directory (other than
 * a directory name starting with dot). Else return 0.	*/
static int
first_dir_scan_select( const struct dirent *s )
{
  if( FT_OTHER != aa_first.ft )
    return 0;
  if( !dir_or_link( s, NULL ) )
    return 0;
  strncpy( aa_first.name, s->d_name, LMAX_NAME );
  aa_first.ft = FT_CHAR;        /* dummy */
  aa_first.d_type = s->d_type;
  return 1;
}

typedef int   ( *dirent_select_fn ) ( const struct dirent * );

/* scan for directory entry that is either a symlink or a directory. Returns
 * number found or -1 for error. */
static int
scan_for_first( const char *dir_name )
{
  int           num, k;
  struct dirent **namelist;

  aa_first.ft = FT_OTHER;
  num = scandir( dir_name, &namelist, first_dir_scan_select, NULL );
  if( num < 0 )
  {
    return -1;
  }
  for( k = 0; k < num; ++k )
    free( namelist[k] );
  free( namelist );
  return num;
}

static int
non_sg_dir_scan_select( const struct dirent *s )
{
  int           len;

  if( FT_OTHER != non_sg.ft )
    return 0;
  if( !dir_or_link( s, NULL ) )
    return 0;
  if( 0 == strncmp( "scsi_changer", s->d_name, 12 ) )
  {
    strncpy( non_sg.name, s->d_name, LMAX_NAME );
    non_sg.ft = FT_CHAR;
    non_sg.d_type = s->d_type;
    return 1;
  }
  else if( 0 == strncmp( "block", s->d_name, 5 ) )
  {
    strncpy( non_sg.name, s->d_name, LMAX_NAME );
    non_sg.ft = FT_BLOCK;
    non_sg.d_type = s->d_type;
    return 1;
  }
  else if( 0 == strcmp( "tape", s->d_name ) )
  {
    strncpy( non_sg.name, s->d_name, LMAX_NAME );
    non_sg.ft = FT_CHAR;
    non_sg.d_type = s->d_type;
    return 1;
  }
  else if( 0 == strncmp( "scsi_tape:st", s->d_name, 12 ) )
  {
    len = strlen( s->d_name );
    if( isdigit( s->d_name[len - 1] ) )
    {
      /* want 'st<num>' symlink only */
      strncpy( non_sg.name, s->d_name, LMAX_NAME );
      non_sg.ft = FT_CHAR;
      non_sg.d_type = s->d_type;
      return 1;
    }
    else
      return 0;
  }
  else if( 0 == strncmp( "onstream_tape:os", s->d_name, 16 ) )
  {
    strncpy( non_sg.name, s->d_name, LMAX_NAME );
    non_sg.ft = FT_CHAR;
    non_sg.d_type = s->d_type;
    return 1;
  }
  else
    return 0;
}

/* Returns number found or -1 for error */
static int
non_sg_scan( const char *dir_name )
{
  int           num, k;
  struct dirent **namelist;

  non_sg.ft = FT_OTHER;
  num = scandir( dir_name, &namelist, non_sg_dir_scan_select, NULL );
  if( num < 0 )
  {
    return -1;
  }
  for( k = 0; k < num; ++k )
    free( namelist[k] );
  free( namelist );
  return num;
}

/* If 'dir_name'/'base_name' is a directory chdir to it. If that is successful
   return true, else false */
static bool
if_directory_chdir( const char *dir_name, const char *base_name )
{
  char          b[2*LMAX_PATH];
  struct stat   a_stat;

  snprintf( b, sizeof( b ), "%s/%s", dir_name, base_name );
  if( stat( b, &a_stat ) < 0 )
    return false;
  if( S_ISDIR( a_stat.st_mode ) )
  {
    if( chdir( b ) < 0 )
      return false;
    return true;
  }
  return false;
}

/* If 'dir_name'/'base_name' is found places corresponding value in 'value'
 * and returns true . Else returns false.
 */
static bool
get_value( const char *dir_name, const char *base_name, char *value,
    int max_value_len )
{
  int           len;
  FILE         *f;
  char          b[LMAX_PATH];

  snprintf( b, sizeof( b ), "%s/%s", dir_name, base_name );
  if( NULL == ( f = fopen( b, "r" ) ) )
  {
    return false;
  }
  if( NULL == fgets( value, max_value_len, f ) )
  {
    /* assume empty */
    value[0] = '\0';
    fclose( f );
    return true;
  }
  len = strlen( value );
  if( ( len > 0 ) && ( value[len - 1] == '\n' ) )
    value[len - 1] = '\0';
  fclose( f );
  return true;
}

/* Allocate dev_node_list and collect info on every char and block devices
 * in /dev but not its subdirectories. This list excludes symlinks, even if
 * they are to devices. */
static void
collect_dev_nodes( void )
{
  size_t        dnl_sz = sizeof( struct dev_node_list );
  struct dirent *dep;
  DIR          *dirp;
  struct dev_node_list *cur_list, *prev_list;
  struct dev_node_entry *cur_ent;
  char          device_path[LMAX_DEVPATH];
  struct stat   stats;

  if( dev_node_listhead )
    return;                     /* already collected nodes */

  dev_node_listhead = ( struct dev_node_list * ) calloc( 1, dnl_sz );
  if( !dev_node_listhead )
    return;

  cur_list = dev_node_listhead;
  cur_list->next = NULL;
  cur_list->count = 0;

  dirp = opendir( dev_dir );
  if( dirp == NULL )
    return;

  while( 1 )
  {
    dep = readdir( dirp );
    if( dep == NULL )
      break;

    snprintf( device_path, sizeof( device_path ), "%s/%s",
        dev_dir, dep->d_name );
    /* device_path[LMAX_PATH] = '\0'; */

    /* This will bypass all symlinks in /dev */
    if( lstat( device_path, &stats ) )
      continue;

    /* Skip non-block/char files. */
    if( ( !S_ISBLK( stats.st_mode ) ) && ( !S_ISCHR( stats.st_mode ) ) )
      continue;

    /* Add to the list. */
    if( cur_list->count >= DEV_NODE_LIST_ENTRIES )
    {
      prev_list = cur_list;
      cur_list = ( struct dev_node_list * ) calloc( 1, dnl_sz );
      if( !cur_list )
        break;
      prev_list->next = cur_list;
      cur_list->next = NULL;
      cur_list->count = 0;
    }

    cur_ent = &cur_list->nodes[cur_list->count];
    cur_ent->maj = major( stats.st_rdev );
    cur_ent->min = minor( stats.st_rdev );
    if( S_ISBLK( stats.st_mode ) )
      cur_ent->type = BLK_DEV;
    else if( S_ISCHR( stats.st_mode ) )
      cur_ent->type = CHR_DEV;
    cur_ent->mtime = stats.st_mtime;
    strncpy( cur_ent->name, device_path, sizeof( cur_ent->name ) );

    cur_list->count++;
  }
  closedir( dirp );
}

/* Free dev_node_list. */
static void
free_dev_node_list( void )
{
  if( dev_node_listhead )
  {
    struct dev_node_list *cur_list, *next_list;

    cur_list = dev_node_listhead;
    while( cur_list )
    {
      next_list = cur_list->next;
      free( cur_list );
      cur_list = next_list;
    }

    dev_node_listhead = NULL;
  }
}

/* Given a path to a class device, find the most recent device node with
 * matching major/minor and type. Outputs to node which is assumed to be at
 * least LMAX_NAME bytes long. Returns true if match found, false
 * otherwise. */
static bool
get_dev_node( const char *wd, char *node, enum dev_type type )
{
  bool          match_found = false;
  unsigned int  k = 0;
  unsigned int  maj, min;
  time_t        newest_mtime = 0;
  struct dev_node_entry *cur_ent;
  struct dev_node_list *cur_list;
  char          value[LMAX_NAME];

  /* assume 'node' is at least 2 bytes long */
  memcpy( node, "-", 2 );
  if( dev_node_listhead == NULL )
  {
    collect_dev_nodes(  );
    if( dev_node_listhead == NULL )
      goto exit;
  }

  /* Get the major/minor for this device. */
  if( !get_value( wd, "dev", value, LMAX_NAME ) )
    goto exit;
  sscanf( value, "%u:%u", &maj, &min );

  /* Search the node list for the newest match on this major/minor. */
  cur_list = dev_node_listhead;

  while( 1 )
  {
    if( k >= cur_list->count )
    {
      cur_list = cur_list->next;
      if( !cur_list )
        break;
      k = 0;
    }

    cur_ent = &cur_list->nodes[k];
    k++;

    if( ( maj == cur_ent->maj ) &&
        ( min == cur_ent->min ) && ( type == cur_ent->type ) )
    {
      if( ( !match_found ) ||
          ( difftime( cur_ent->mtime, newest_mtime ) > 0 ) )
      {
        newest_mtime = cur_ent->mtime;
        strncpy( node, cur_ent->name, LMAX_NAME - 1 );
      }
      match_found = true;
    }
  }

exit:
  return match_found;
}

/* Return true for direct access, cd/dvd, rbc and host managed zbc */
static inline bool
is_direct_access_dev( int pdt )
{
  return ( ( 0x0 == pdt ) || ( 0x5 == pdt ) || ( 0xe == pdt ) ||
      ( 0x14 == pdt ) );
}

/* List one SCSI device (LU) */
static char *
one_sdev_entry( const char *dir_name, const char *devname )
{
  int           vlen;
  char          buff[LMAX_DEVPATH];
  char          extra[LMAX_DEVPATH];
  char          value[LMAX_NAME];
  char          wd[LMAX_PATH];
  static char   dev_node[LMAX_NAME] = "";
  enum dev_type typ;

  vlen = sizeof( value );
  snprintf( buff, sizeof( buff ), "%s/%s", dir_name, devname );
  if( !get_value( buff, "vendor", value, vlen ) )
    return NULL;
  if( strncmp( value, "WD", 2 ) )
    return NULL;
  if( !get_value( buff, "model", value, vlen ) )
    return NULL;
  if( strstr( value, "Passport" ) == NULL )
    return NULL;

  if( 1 != non_sg_scan( buff ) )
    return NULL;
  if( DT_DIR == non_sg.d_type )
  {
    snprintf( wd, sizeof( wd ), "%s/%s", buff, non_sg.name );
    if( 1 == scan_for_first( wd ) )
      strncpy( extra, aa_first.name, sizeof( extra ) );
    else
      return NULL;
  }
  else
  {
    strncpy( wd, buff, sizeof( wd ) );
    strncpy( extra, non_sg.name, sizeof( extra ) );
  }
  if( ( if_directory_chdir( wd, extra ) ) )
  {
    if( NULL == getcwd( wd, sizeof( wd ) ) )
      return NULL;
  }
  typ = ( FT_BLOCK == non_sg.ft ) ? BLK_DEV : CHR_DEV;
  if( !get_dev_node( wd, dev_node, typ ) )
    return NULL;
  return dev_node;
}

/* List SCSI devices (LUs). */
static char  *
list_sdevices( void )
{
  int           num, k, blen, nlen;
  struct dirent **namelist;
  char          buff[LMAX_DEVPATH];
  char          name[LMAX_NAME];
  char         *wd_pass_dev = NULL;

  blen = sizeof( buff );
  nlen = sizeof( name );
  snprintf( buff, blen, "%s%s", sysfsroot, bus_scsi_devs );

  num = scandir( buff, &namelist, NULL, NULL );
  if( num < 0 )
  {                             /* scsi mid level may not be loaded */
    return NULL;
  }

  for( k = 0; k < num; ++k )
  {
    strncpy( name, namelist[k]->d_name, nlen );
    if( wd_pass_dev == NULL )
      wd_pass_dev = one_sdev_entry( buff, name );
    free( namelist[k] );
  }
  free( namelist );
  return wd_pass_dev;
}

char         *
find_passport_device( void )
{
  char         path[1024];
  char         *wd_pass_dev;

  getcwd( path, 1024 );
  wd_pass_dev = list_sdevices(  );
  free_dev_node_list(  );
  chdir( path );
  return wd_pass_dev;
}
