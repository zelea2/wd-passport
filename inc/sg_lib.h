#ifndef SG_LIB_H
#define SG_LIB_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* SCSI Peripheral Device Types (PDT) [5 bit field] */
#define PDT_DISK 0x0            /* direct access block device (disk) */
#define PDT_TAPE 0x1            /* sequential access device (magnetic tape) */
#define PDT_PRINTER 0x2         /* printer device (see SSC-1) */
#define PDT_PROCESSOR 0x3       /* processor device (e.g. SAFTE device) */
#define PDT_WO 0x4              /* write once device (some optical disks) */
#define PDT_MMC 0x5             /* CD/DVD/BD (multi-media) */
#define PDT_SCANNER 0x6         /* obsolete */
#define PDT_OPTICAL 0x7         /* optical memory device (some optical disks) */
#define PDT_MCHANGER 0x8        /* media changer device (e.g. tape robot) */
#define PDT_COMMS 0x9           /* communications device (obsolete) */
#define PDT_SAC 0xc             /* storage array controller device */
#define PDT_SES 0xd             /* SCSI Enclosure Services (SES) device */
#define PDT_RBC 0xe             /* Reduced Block Commands (simplified PDT_DISK) */
#define PDT_OCRW 0xf            /* optical card read/write device */
#define PDT_BCC 0x10            /* bridge controller commands */
#define PDT_OSD 0x11            /* Object Storage Device (OSD) */
#define PDT_ADC 0x12            /* Automation/drive commands (ADC) */
#define PDT_SMD 0x13            /* Security Manager Device (SMD) */
#define PDT_ZBC 0x14            /* Zoned Block Commands (ZBC) */
#define PDT_WLUN 0x1e           /* Well known logical unit (WLUN) */
#define PDT_UNKNOWN 0x1f        /* Unknown or no device type */

#ifndef SAM_STAT_GOOD
#define SAM_STAT_GOOD 0x0
#define SAM_STAT_CHECK_CONDITION 0x2
#define SAM_STAT_CONDITION_MET 0x4
#define SAM_STAT_BUSY 0x8
#define SAM_STAT_INTERMEDIATE 0x10      /* obsolete in SAM-4 */
#define SAM_STAT_INTERMEDIATE_CONDITION_MET 0x14        /* obsolete in SAM-4 */
#define SAM_STAT_RESERVATION_CONFLICT 0x18
#define SAM_STAT_COMMAND_TERMINATED 0x22        /* obsolete in SAM-3 */
#define SAM_STAT_TASK_SET_FULL 0x28
#define SAM_STAT_ACA_ACTIVE 0x30
#define SAM_STAT_TASK_ABORTED 0x40
#endif

/* The SCSI sense key codes as found in SPC-4 at www.t10.org */
#define SPC_SK_NO_SENSE 0x0
#define SPC_SK_RECOVERED_ERROR 0x1
#define SPC_SK_NOT_READY 0x2
#define SPC_SK_MEDIUM_ERROR 0x3
#define SPC_SK_HARDWARE_ERROR 0x4
#define SPC_SK_ILLEGAL_REQUEST 0x5
#define SPC_SK_UNIT_ATTENTION 0x6
#define SPC_SK_DATA_PROTECT 0x7
#define SPC_SK_BLANK_CHECK 0x8
#define SPC_SK_VENDOR_SPECIFIC 0x9
#define SPC_SK_COPY_ABORTED 0xa
#define SPC_SK_ABORTED_COMMAND 0xb
#define SPC_SK_RESERVED 0xc
#define SPC_SK_VOLUME_OVERFLOW 0xd
#define SPC_SK_MISCOMPARE 0xe
#define SPC_SK_COMPLETED 0xf

#define SG_LIB_SYNTAX_ERROR 1   /* command line syntax problem */
#define SG_LIB_CAT_NOT_READY 2  /* sense key, unit stopped? [sk,asc,ascq: 0x2,*,*] */
#define SG_LIB_CAT_MEDIUM_HARD 3        /* medium or hardware error, blank check [sk,asc,ascq: 0x3/0x4/0x8,*,*] */
#define SG_LIB_CAT_ILLEGAL_REQ 5        /* Illegal request (other than invalid opcode): [sk,asc,ascq: 0x5,*,*] */
#define SG_LIB_CAT_UNIT_ATTENTION 6     /* sense key, device state changed [sk,asc,ascq: 0x6,*,*] */
#define SG_LIB_CAT_DATA_PROTECT 7       /* sense key, media write protected? [sk,asc,ascq: 0x7,*,*] */
#define SG_LIB_CAT_INVALID_OP 9 /* (Illegal request,) Invalid opcode: [sk,asc,ascq: 0x5,0x20,0x0] */
#define SG_LIB_CAT_COPY_ABORTED 10      /* sense key, some data transferred [sk,asc,ascq: 0xa,*,*] */
#define SG_LIB_CAT_ABORTED_COMMAND 11   /* interpreted from sense buffer [sk,asc,ascq: 0xb,! 0x10,*] */
#define SG_LIB_CAT_MISCOMPARE 14        /* sense key, probably verify [sk,asc,ascq: 0xe,*,*] */
#define SG_LIB_CAT_NO_SENSE 20  /* sense data with key of "no sense" [sk,asc,ascq: 0x0,*,*] */
#define SG_LIB_CAT_RECOVERED 21 /* Successful command after recovered err [sk,asc,ascq: 0x1,*,*] */
#define SG_LIB_LBA_OUT_OF_RANGE 22      /* Illegal request, LBA Out Of Range [sk,asc,ascq: 0x5,0x21,0x0] */
#define SG_LIB_CAT_RES_CONFLICT 24 /* this is a SCSI status, not sense. It indicates reservation by another machine blocks this command */
#define SG_LIB_LOGIC_ERROR 32   /* unexpected situation in code */
#define SG_LIB_CAT_TIMEOUT 33   /* SCSI command timeout */
#define SG_LIB_OK_FALSE 36      /* no error, reporting false (cf. no error, reporting true is SG_LIB_OK_TRUE(0) ) */
#define SG_LIB_CAT_PROTECTION 40        /* subset of aborted command (for PI, DIF) [sk,asc,ascq: 0xb,0x10,*] */
#define SG_LIB_OS_BASE_ERR 50   /* in Linux: values found in: include/uapi/asm-generic/errno-base.h Example: ENOMEM reported as 62 (=50+12) if errno > 46 then
                                 * use this value */
#define SG_LIB_CAT_MALFORMED 97 /* Response to SCSI command malformed */
#define SG_LIB_CAT_SENSE 98     /* Something else is in the sense buffer */
#define SG_LIB_CAT_OTHER 99     /* Some other error/warning has occurred (e.g. a transport or driver error) */

/* This is a slightly stretched SCSI sense "descriptor" format header.
 * The addition is to allow the 0x70 and 0x71 response codes. The idea
 * is to place the salient data of both "fixed" and "descriptor" sense
 * format into one structure to ease application processing.
 * The original sense buffer should be kept around for those cases
 * in which more information is required (e.g. the LBA of a MEDIUM ERROR). */
struct sg_scsi_sense_hdr
{
  uint8_t       response_code;        /* permit: 0x0, 0x70, 0x71, 0x72, 0x73 */
  uint8_t       sense_key;
  uint8_t       asc;
  uint8_t       ascq;
  uint8_t       byte4;        /* descriptor: SDAT_OVFL; fixed: lower three ... */
  uint8_t       byte5;        /* ... bytes of INFO field */
  uint8_t       byte6;
  uint8_t       additional_length;    /* zero for fixed format sense data */
};

#if (__STDC_VERSION__ >= 199901L)       /* C99 or later */
  typedef uintptr_t sg_uintptr_t;
#else
    typedef unsigned long sg_uintptr_t;
#endif

/* Borrowed from Linux kernel; no check that 'arr' actually is one */
#define SG_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int pr2ws(const char *fmt, ...);
int pr2serr( const char *fmt, ... );
_Bool sg_scsi_normalize_sense(const uint8_t *sbp, int sb_len, struct sg_scsi_sense_hdr *sshp);
int hex2str(const uint8_t *b_str, int len, const char *leadin, int format, int b_len, char *b);
void hex2stderr(const uint8_t *b_str, int len, int no_ascii);
char *safe_strerror(int errnum);
int sg_convert_errno(int os_err_num);
uint8_t *sg_memalign(uint32_t num_bytes, uint32_t align_to, uint8_t **buff_to_free, _Bool vb);
int sg_scnpr(char *cp, int cp_max_len, const char *fmt, ...);
const char *sg_get_category_sense_str(int sense_cat, int b_len, char *b, int verbose);
void sg_get_command_name(const uint8_t *cdbp, int peri_type, int buff_len, char *buff);
char *sg_get_command_str(const uint8_t *cdbp, int sz, _Bool cmd_name, int blen, char *b);
int sg_get_command_size(uint8_t opcode);
void sg_get_opcode_name(uint8_t cmd_byte0, int peri_type, int buff_len, char *buff);
void sg_get_opcode_sa_name(uint8_t cmd_byte0, int service_action, 
    int peri_type, int buff_len, char *buff);
int sg_lib_pdt_decay(int pdt);
uint32_t sg_get_page_size(void);
int sg_err_category_sense(const uint8_t *sbp, int sb_len);
void sg_print_sense(const char *leadin, const uint8_t *sbp, int sb_len, _Bool raw_sinfo);

#endif                          /* SG_LIB_H */
