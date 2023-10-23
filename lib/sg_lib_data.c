#include <stdlib.h>

#include "sg_lib.h"
#include "sg_lib_data.h"

/* indexed by pdt; those that map to own index do not decay */
int           sg_lib_pdt_decay_arr[32] = {
  PDT_DISK, PDT_TAPE, PDT_TAPE /* printer */ , PDT_PROCESSOR,
  PDT_DISK /* WO */ , PDT_MMC, PDT_SCANNER, PDT_DISK /* optical */ ,
  PDT_MCHANGER, PDT_COMMS, 0xa, 0xb,
  PDT_SAC, PDT_SES, PDT_DISK /* rbc */ , PDT_OCRW,
  PDT_BCC, PDT_OSD, PDT_TAPE /* adc */ , PDT_SMD,
  PDT_DISK /* zbc */ , 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, PDT_WLUN, PDT_UNKNOWN
};

struct sg_lib_value_name_t sg_lib_normal_opcodes[] = {
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_read_buff_arr[] = {   /* opcode 0x3c */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_write_buff_arr[] = {  /* opcode 0x3b */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_read_pos_arr[] = {    /* opcode 0x34 (SSC) */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_maint_in_arr[] = {    /* opcode 0xa3 */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_maint_out_arr[] = {   /* opcode 0xa4 */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_sanitize_sa_arr[] = { /* opcode 0x94 */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_serv_in12_arr[] = {   /* opcode 0xab */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_serv_out12_arr[] = {  /* opcode 0xa9 */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_serv_in16_arr[] = {   /* opcode 0x9e */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_serv_out16_arr[] = {  /* opcode 0x9f */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_serv_bidi_arr[] = {   /* opcode 0x9d */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_pr_in_arr[] = {       /* opcode 0x5e */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_pr_out_arr[] = {      /* opcode 0x5f */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_xcopy_sa_arr[] = {    /* opcode 0x83 */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_rec_copy_sa_arr[] = { /* opcode 0x84 */
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_variable_length_arr[] = {
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_zoning_out_arr[] = {
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_zoning_in_arr[] = {
  {0xffff, 0, NULL},
};

struct sg_lib_value_name_t sg_lib_read_attr_arr[] = {
  {0xffff, 0, NULL},
};

/* A conveniently formatted list of SCSI ASC/ASCQ codes and their
 * corresponding text can be found at: www.t10.org/lists/asc-num.txt
 * The following should match asc-num.txt dated 20200817 */

struct sg_lib_asc_ascq_range_t sg_lib_asc_ascq_range[] = {
  {0, 0, 0, NULL}
};

struct sg_lib_asc_ascq_t sg_lib_asc_ascq[] = {
  {0, 0, NULL}
};

const char   *sg_lib_sense_key_desc[] = {
  "No Sense",                   /* Filemark, ILI and/or EOM; progress indication (during FORMAT); power condition sensing (REQUEST SENSE) */
  "Recovered Error",            /* The last command completed successfully but used error correction */
  "Not Ready",                  /* The addressed target is not ready */
  "Medium Error",               /* Data error detected on the medium */
  "Hardware Error",             /* Controller or device failure */
  "Illegal Request",
  "Unit Attention",             /* Removable medium was changed, or the target has been reset */
  "Data Protect",               /* Access to the data is blocked */
  "Blank Check",                /* Reached unexpected written or unwritten region of the medium */
  "Vendor specific(9)",         /* Vendor specific */
  "Copy Aborted",               /* COPY or COMPARE was aborted */
  "Aborted Command",            /* The target aborted the command */
  "Equal",                      /* SEARCH DATA found data equal (obsolete) */
  "Volume Overflow",            /* Medium full with data to be written */
  "Miscompare",                 /* Source data and data on the medium do not agree */
  "Completed"                   /* may occur for successful cmd (spc4r23) */
};

const char   *sg_lib_pdt_strs[32] = {   /* should have 2**5 elements */
  /* 0 */ "disk",
  "tape",
  "printer",                    /* obsolete, spc5r01 */
  "processor",                  /* often SAF-TE device, copy manager */
  "write once optical disk",    /* obsolete, spc5r01 */
  /* 5 */ "cd/dvd",
  "scanner",                    /* obsolete */
  "optical memory device",
  "medium changer",
  "communications",             /* obsolete */
                                /* 0xa */ "graphics [0xa]",
                                /* obsolete */
  "graphics [0xb]",             /* obsolete */
  "storage array controller",
  "enclosure services device",
  "simplified direct access device",
  "optical card reader/writer device",
  /* 0x10 */ "bridge controller commands",
  "object based storage",
  "automation/driver interface",
  "security manager device",    /* obsolete, spc5r01 */
  "host managed zoned block",
  "0x15", "0x16", "0x17", "0x18",
  "0x19", "0x1a", "0x1b", "0x1c", "0x1d",
  "well known logical unit",
  "unknown or no device type",  /* coupled with PQ=3 for not accessible via this lu's port (try the other) */
};

const char   *sg_lib_transport_proto_strs[] = {
  "Fibre Channel Protocol for SCSI (FCP-5)",    /* now at fcp5r01 */
  "SCSI Parallel Interface (SPI-5)",    /* obsolete in spc5r01 */
  "Serial Storage Architecture SCSI-3 Protocol (SSA-S3P)",
  "Serial Bus Protocol for IEEE 1394 (SBP-3)",
  "SCSI RDMA Protocol (SRP)",
  "Internet SCSI (iSCSI)",
  "Serial Attached SCSI Protocol (SPL-4)",
  "Automation/Drive Interface Transport (ADT-2)",
  "AT Attachment Interface (ACS-2)",    /* 0x8 */
  "USB Attached SCSI (UAS-2)",
  "SCSI over PCI Express (SOP)",
  "PCIe",                       /* added in spc5r02 */
  "Oxc", "Oxd", "Oxe",
  "No specific protocol"
};

struct sg_lib_simple_value_name_t sg_lib_nvme_admin_cmd_arr[] = {

  /* Vendor specific 0x80 to 0xff */
  {0xffff, NULL},               /* Sentinel */
};

struct sg_lib_simple_value_name_t sg_lib_nvme_nvm_cmd_arr[] = {

  /* Vendor specific 0x80 to 0xff */
  {0xffff, NULL},               /* Sentinel */
};

struct sg_lib_value_name_t sg_lib_nvme_cmd_status_arr[] = {

  /* Leave this Sentinel value at end of this array */
  {0x3ff, 0, NULL},
};

struct sg_lib_4tuple_u8 sg_lib_scsi_status_sense_arr[] = {

  /* Leave this Sentinel value at end of this array */
  {0xff, 0xff, 0xff, 0xff},
};

struct sg_value_2names_t sg_exit_str_arr[] = {
  {0xffff, NULL, NULL},         /* end marking sentinel */
};
