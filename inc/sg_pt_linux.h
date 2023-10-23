#ifndef SG_PT_LINUX_H
#define SG_PT_LINUX_H

#include <stdint.h>
#include <stdbool.h>
#include <scsi/sg.h>
#include <scsi/scsi.h>

#include <linux/types.h>

#include <linux/bsg.h>

#define CDB_LENGTH 10
#define MIN_SCSI_CDBSZ 6
#define MAX_SCSI_CDBSZ 260
#define MAX_SCSI_XFER 512
#define SCSI_TIMEOUT 20

struct scsi_op_t
{
  bool          dir_inout;
  int           data_len;
  char         *device_name;
};

struct sg_sntl_dev_state_t
{
  uint8_t       scsi_dsense;
  uint8_t       enclosure_override;	/* ENC_OV in sdparm */
  uint8_t       pdt;		/* 6 bit value in INQUIRY response */
  uint8_t       enc_serv;	/* single bit in INQUIRY response */
  uint8_t       id_ctl253;	/* NVMSR field of Identify controller (byte
				 * 253) */
  bool          wce;		/* Write Cache Enable (WCE) setting */
  bool          wce_changed;	/* WCE setting has been changed */
};

struct sg_sntl_result_t
{
  uint8_t       sstatus;
  uint8_t       sk;
  uint8_t       asc;
  uint8_t       ascq;
  uint8_t       in_byte;
  uint8_t       in_bit;		/* use 255 for 'no bit position given' */
};

struct sg_opcode_info_t
{
  uint8_t       opcode;
  uint16_t      sa;		/* service action, 0 for none */
  uint32_t      flags;		/* OR-ed set of F_* flags */
  uint8_t       len_mask[16];	/* len=len_mask[0], then mask for cdb[1]... */
  /*
   * ignore cdb bytes after position 15 
   */
};

struct sg_pt_linux_scsi
{
  struct sg_io_v4 io_hdr;	/* use v4 header as it is more general */
  /*
   * Leave io_hdr in first place of this structure 
   */
  bool          is_sg;
  bool          is_bsg;
  bool          mdxfer_out;	/* direction of metadata xfer, true->data-out 
				 */
  int           dev_fd;		/* -1 if not given (yet) */
  int           in_err;
  int           os_err;
  int           sg_version;	/* for deciding whether to use v3 or v4
				 * interface */
  uint32_t      mdxfer_len;
  struct sg_sntl_dev_state_t dev_stat;
  void         *mdxferp;
  uint8_t      *nvme_id_ctlp;	/* cached response to controller IDENTIFY */
  uint8_t      *free_nvme_id_ctlp;
  uint8_t       tmf_request[4];
};

struct sg_pt_base
{
  struct sg_pt_linux_scsi impl;
};

#ifndef sg_nvme_admin_cmd
#define sg_nvme_admin_cmd sg_nvme_passthru_cmd
#endif

/* Linux NVMe related ioctls */
#ifndef NVME_IOCTL_ID
#define NVME_IOCTL_ID		_IO('N', 0x40)
#endif
#ifndef NVME_IOCTL_ADMIN_CMD
#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct sg_nvme_admin_cmd)
#endif
#ifndef NVME_IOCTL_SUBMIT_IO
#define NVME_IOCTL_SUBMIT_IO	_IOW('N', 0x42, struct sg_nvme_user_io)
#endif
#ifndef NVME_IOCTL_IO_CMD
#define NVME_IOCTL_IO_CMD	_IOWR('N', 0x43, struct sg_nvme_passthru_cmd)
#endif
#ifndef NVME_IOCTL_RESET
#define NVME_IOCTL_RESET	_IO('N', 0x44)
#endif
#ifndef NVME_IOCTL_SUBSYS_RESET
#define NVME_IOCTL_SUBSYS_RESET _IO('N', 0x45)
#endif
#ifndef NVME_IOCTL_RESCAN
#define NVME_IOCTL_RESCAN	_IO('N', 0x46)
#endif

extern bool   sg_bsg_nvme_char_major_checked;
extern int    sg_bsg_major;
extern volatile int sg_nvme_char_major;
extern long   sg_lin_page_size;
extern uint8_t  cdb[CDB_LENGTH];
extern uint8_t  cmdout[MAX_SCSI_XFER];
extern uint8_t  reply[MAX_SCSI_XFER];

void          sg_find_bsg_nvme_char_major( int verbose );
int           sg_do_nvme_pt( struct sg_pt_base *vp, int fd, 
                             int time_secs, int vb );
int           sg_linux_get_sg_version( const struct sg_pt_base *vp );
int           scsi_xfer( struct scsi_op_t *op );

#endif				/* end of SG_PT_LINUX_H */
