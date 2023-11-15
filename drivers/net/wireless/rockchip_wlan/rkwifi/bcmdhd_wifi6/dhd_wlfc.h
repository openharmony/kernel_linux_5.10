/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 1999-2019, Broadcom.
 *
 *      Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2 (the "GPL"),
 * available at http://www.broadcom.com/licenses/GPLv2.php, with the
 * following added to such license:
 *
 *      As a special exception, the copyright holders of this software give you
 * permission to link this software with independent modules, and to copy and
 * distribute the resulting executable under terms of your choice, provided that
 * you also meet, for each linked independent module, the terms and conditions of
 * the license of that module.  An independent module is a module which is not
 * derived from this software.  The special exception does not apply to any
 * modifications of the software.
 *
 *      Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 * $Id: dhd_wlfc.h 690477 2017-03-16 10:17:17Z $
 *
 */
#ifndef __wlfc_host_driver_definitions_h__
#define __wlfc_host_driver_definitions_h__

#include <bcmsdbus.h>
#include <bcmsdpcm.h>
#include <sbsdpcmdev.h>
#include <hnd_cons.h>
/* #define OOO_DEBUG */

#define KERNEL_THREAD_RETURN_TYPE int

typedef struct dhd_console {
	 uint		count;	/* Poll interval msec counter */
	 uint		log_addr;		 /* Log struct address (fixed) */
	 hnd_log_t	 log;			 /* Log struct (host copy) */
	 uint		 bufsize;		 /* Size of log buffer */
	 uint8		 *buf;			 /* Log buffer (host copy) */
	 uint		 last;			 /* Last buffer read index */
} dhd_console_t;

typedef int (*f_commitpkt_t)(struct dhd_bus* ctx, void* p);
typedef bool (*f_processpkt_t)(void* p, void* arg);

#define WLFC_UNSUPPORTED -9999

#define WLFC_NO_TRAFFIC	-1
#define WLFC_MULTI_TRAFFIC 0

#define BUS_RETRIES 1	/* # of retries before aborting a bus tx operation */

/* Space for header read, limit for data packets */
#ifndef MAX_HDR_READ
#define MAX_HDR_READ	32
#endif // endif
/** 16 bits will provide an absolute max of 65536 slots */
#define WLFC_HANGER_MAXITEMS 3072

#define WLFC_HANGER_ITEM_STATE_FREE			1
#define WLFC_HANGER_ITEM_STATE_INUSE			2
#define WLFC_HANGER_ITEM_STATE_INUSE_SUPPRESSED		3
#define WLFC_HANGER_ITEM_STATE_FLUSHED			4

#define WLFC_HANGER_PKT_STATE_TXSTATUS			1
#define WLFC_HANGER_PKT_STATE_BUSRETURNED		2
#define WLFC_HANGER_PKT_STATE_COMPLETE			\
	(WLFC_HANGER_PKT_STATE_TXSTATUS | WLFC_HANGER_PKT_STATE_BUSRETURNED)

/* Private data for SDIO bus interaction */
typedef struct dhd_bus {
	dhd_pub_t	*dhd;

	bcmsdh_info_t	*sdh;			/* Handle for BCMSDH calls */
	si_t		*sih;			/* Handle for SI calls */
	char		*vars;			/* Variables (from CIS and/or other) */
	uint		varsz;			/* Size of variables buffer */
	uint32		sbaddr;			/* Current SB window pointer (-1, invalid) */

	sdpcmd_regs_t	*regs;			/* Registers for SDIO core */
	uint		sdpcmrev;		/* SDIO core revision */
	uint		armrev;			/* CPU core revision */
	uint		ramrev;			/* SOCRAM core revision */
	uint32		ramsize;		/* Size of RAM in SOCRAM (bytes) */
	uint32		orig_ramsize;		/* Size of RAM in SOCRAM (bytes) */
	uint32		srmemsize;		/* Size of SRMEM */

	uint32		bus;			/* gSPI or SDIO bus */
	uint32		bus_num;		/* bus number */
	uint32		slot_num;		/* slot ID */
	uint32		hostintmask;	/* Copy of Host Interrupt Mask */
	uint32		intstatus;		/* Intstatus bits (events) pending */
	bool		dpc_sched;		/* Indicates DPC schedule (intrpt rcvd) */
	bool		fcstate;		/* State of dongle flow-control */

	uint16		cl_devid;		/* cached devid for dhdsdio_probe_attach() */
	char		*fw_path;		/* module_param: path to firmware image */
	char		*nv_path;		/* module_param: path to nvram vars file */

	uint		blocksize;		/* Block size of SDIO transfers */
	uint		roundup;		/* Max roundup limit */

	struct pktq	txq;			/* Queue length used for flow-control */
	uint8		flowcontrol;		/* per prio flow control bitmask */
	uint8		tx_seq;			/* Transmit sequence number (next) */
	uint8		tx_max;			/* Maximum transmit sequence allowed */

#ifdef DYNAMIC_MAX_HDR_READ
	uint8		*hdrbufp;
#else
	uint8		hdrbuf[MAX_HDR_READ + DHD_SDALIGN];
#endif
	uint8		*rxhdr;			/* Header of current rx frame (in hdrbuf) */
	uint16		nextlen;		/* Next Read Len from last header */
	uint8		rx_seq;			/* Receive sequence number (expected) */
	bool		rxskip;			/* Skip receive (awaiting NAK ACK) */

	void		*glomd;			/* Packet containing glomming descriptor */
	void		*glom;			/* Packet chain for glommed superframe */
	uint		glomerr;		/* Glom packet read errors */

	uint8		*rxbuf;			/* Buffer for receiving control packets */
	uint		rxblen;			/* Allocated length of rxbuf */
	uint8		*rxctl;			/* Aligned pointer into rxbuf */
	uint8		*databuf;		/* Buffer for receiving big glom packet */
	uint8		*dataptr;		/* Aligned pointer into databuf */
	uint		rxlen;			/* Length of valid data in buffer */

	uint8		sdpcm_ver;		/* Bus protocol reported by dongle */

	bool		intr;			/* Use interrupts */
	bool		poll;			/* Use polling */
	bool		ipend;			/* Device interrupt is pending */
	bool		intdis;			/* Interrupts disabled by isr */
	uint 		intrcount;		/* Count of device interrupt callbacks */
	uint		lastintrs;		/* Count as of last watchdog timer */
	uint		spurious;		/* Count of spurious interrupts */
	uint		pollrate;		/* Ticks between device polls */
	uint		polltick;		/* Tick counter */
	uint		pollcnt;		/* Count of active polls */

	dhd_console_t	console;		/* Console output polling support */
	uint		console_addr;		/* Console address from shared struct */

	uint		regfails;		/* Count of R_REG/W_REG failures */

	uint		clkstate;		/* State of sd and backplane clock(s) */
	bool		activity;		/* Activity flag for clock down */
	int32		idletime;		/* Control for activity timeout */
	int32		idlecount;		/* Activity timeout counter */
	int32		idleclock;		/* How to set bus driver when idle */
	int32		sd_divisor;		/* Speed control to bus driver */
	int32		sd_mode;		/* Mode control to bus driver */
	int32		sd_rxchain;		/* If bcmsdh api accepts PKT chains */
	bool		use_rxchain;		/* If dhd should use PKT chains */
	bool		sleeping;		/* Is SDIO bus sleeping? */
#if defined(SUPPORT_P2P_GO_PS)
	wait_queue_head_t bus_sleep;
#endif /* LINUX && SUPPORT_P2P_GO_PS */
	bool		ctrl_wait;
	wait_queue_head_t ctrl_tx_wait;
	uint		rxflow_mode;		/* Rx flow control mode */
	bool		rxflow;			/* Is rx flow control on */
	uint		prev_rxlim_hit;		/* Is prev rx limit exceeded (per dpc schedule) */
	bool		alp_only;		/* Don't use HT clock (ALP only) */
	/* Field to decide if rx of control frames happen in rxbuf or lb-pool */
	bool		usebufpool;
	int32		txinrx_thres;	/* num of in-queued pkts */
	int32		dotxinrx;	/* tx first in dhdsdio_readframes */
#ifdef BCMSDIO_RXLIM_POST
	bool		rxlim_en;
	uint32		rxlim_addr;
#endif /* BCMSDIO_RXLIM_POST */
#ifdef SDTEST
	/* external loopback */
	bool		ext_loop;
	uint8		loopid;

	/* pktgen configuration */
	uint		pktgen_freq;		/* Ticks between bursts */
	uint		pktgen_count;		/* Packets to send each burst */
	uint		pktgen_print;		/* Bursts between count displays */
	uint		pktgen_total;		/* Stop after this many */
	uint		pktgen_minlen;		/* Minimum packet data len */
	uint		pktgen_maxlen;		/* Maximum packet data len */
	uint		pktgen_mode;		/* Configured mode: tx, rx, or echo */
	uint		pktgen_stop;		/* Number of tx failures causing stop */

	/* active pktgen fields */
	uint		pktgen_tick;		/* Tick counter for bursts */
	uint		pktgen_ptick;		/* Burst counter for printing */
	uint		pktgen_sent;		/* Number of test packets generated */
	uint		pktgen_rcvd;		/* Number of test packets received */
	uint		pktgen_prev_time;	/* Time at which previous stats where printed */
	uint		pktgen_prev_sent;	/* Number of test packets generated when
						 * previous stats were printed
						 */
	uint		pktgen_prev_rcvd;	/* Number of test packets received when
						 * previous stats were printed
						 */
	uint		pktgen_fail;		/* Number of failed send attempts */
	uint16		pktgen_len;		/* Length of next packet to send */
#define PKTGEN_RCV_IDLE     (0)
#define PKTGEN_RCV_ONGOING  (1)
	uint16		pktgen_rcv_state;		/* receive state */
	uint		pktgen_rcvd_rcvsession;	/* test pkts rcvd per rcv session. */
#endif /* SDTEST */

	/* Some additional counters */
	uint		tx_sderrs;		/* Count of tx attempts with sd errors */
	uint		fcqueued;		/* Tx packets that got queued */
	uint		rxrtx;			/* Count of rtx requests (NAK to dongle) */
	uint		rx_toolong;		/* Receive frames too long to receive */
	uint		rxc_errors;		/* SDIO errors when reading control frames */
	uint		rx_hdrfail;		/* SDIO errors on header reads */
	uint		rx_badhdr;		/* Bad received headers (roosync?) */
	uint		rx_badseq;		/* Mismatched rx sequence number */
	uint		fc_rcvd;		/* Number of flow-control events received */
	uint		fc_xoff;		/* Number which turned on flow-control */
	uint		fc_xon;			/* Number which turned off flow-control */
	uint		rxglomfail;		/* Failed deglom attempts */
	uint		rxglomframes;		/* Number of glom frames (superframes) */
	uint		rxglompkts;		/* Number of packets from glom frames */
	uint		f2rxhdrs;		/* Number of header reads */
	uint		f2rxdata;		/* Number of frame data reads */
	uint		f2txdata;		/* Number of f2 frame writes */
	uint		f1regdata;		/* Number of f1 register accesses */
	wake_counts_t	wake_counts;		/* Wake up counter */
#ifdef BCMSPI
	bool		dwordmode;
#endif /* BCMSPI */
#ifdef DHDENABLE_TAILPAD
	uint		tx_tailpad_chain;	/* Number of tail padding by chaining pad_pkt */
	uint		tx_tailpad_pktget;	/* Number of tail padding by new PKTGET */
#endif /* DHDENABLE_TAILPAD */
	uint8		*ctrl_frame_buf;
	uint32		ctrl_frame_len;
	bool		ctrl_frame_stat;
#ifndef BCMSPI
	uint32		rxint_mode;	/* rx interrupt mode */
#endif /* BCMSPI */
	bool		remap;		/* Contiguous 1MB RAM: 512K socram + 512K devram
					 * Available with socram rev 16
					 * Remap region not DMA-able
					 */
	bool		kso;
	bool		_slpauto;
	bool		_oobwakeup;
	bool		_srenab;
	bool        readframes;
	bool        reqbussleep;
	uint32		resetinstr;
	uint32		dongle_ram_base;

	void		*glom_pkt_arr[SDPCM_MAXGLOM_SIZE];	/* Array of pkts for glomming */
	uint32		txglom_cnt;	/* Number of pkts in the glom array */
	uint32		txglom_total_len;	/* Total length of pkts in glom array */
	bool		txglom_enable;	/* Flag to indicate whether tx glom is enabled/disabled */
	uint32		txglomsize;	/* Glom size limitation */
#ifdef DHDENABLE_TAILPAD
	void		*pad_pkt;
#endif /* DHDENABLE_TAILPAD */
	uint32		dongle_trap_addr; /* device trap addr location in device memory */
#if defined(BT_OVER_SDIO)
	char		*btfw_path;	/* module_param: path to BT firmware image */
	uint32		bt_use_count; /* Counter that tracks whether BT is using the bus */
#endif /* defined (BT_OVER_SDIO) */
	uint		txglomframes;	/* Number of tx glom frames (superframes) */
	uint		txglompkts;		/* Number of packets from tx glom frames */
#ifdef PKT_STATICS
	struct pkt_statics tx_statics;
#endif
	uint8		*membuf;		/* Buffer for dhdsdio_membytes */
#ifdef CONSOLE_DPC
	char		cons_cmd[16];
#endif
} dhd_bus_t;

typedef enum {
	Q_TYPE_PSQ, /**< Power Save Queue, contains both delayed and suppressed packets */
	Q_TYPE_AFQ  /**< At Firmware Queue */
} q_type_t;

typedef enum ewlfc_packet_state {
	eWLFC_PKTTYPE_NEW,        /**< unused in the code (Jan 2015) */
	eWLFC_PKTTYPE_DELAYED,    /**< packet did not enter wlfc yet */
	eWLFC_PKTTYPE_SUPPRESSED, /**< packet entered wlfc and was suppressed by the dongle */
	eWLFC_PKTTYPE_MAX
} ewlfc_packet_state_t;

typedef enum ewlfc_mac_entry_action {
	eWLFC_MAC_ENTRY_ACTION_ADD,
	eWLFC_MAC_ENTRY_ACTION_DEL,
	eWLFC_MAC_ENTRY_ACTION_UPDATE,
	eWLFC_MAC_ENTRY_ACTION_MAX
} ewlfc_mac_entry_action_t;

typedef struct wlfc_hanger_item {
	uint8	state;
	uint8   gen;
	uint8	pkt_state;     /**< bitmask containing eg WLFC_HANGER_PKT_STATE_TXCOMPLETE */
	uint8	pkt_txstatus;
	uint32	identifier;
	void*	pkt;
#ifdef PROP_TXSTATUS_DEBUG
	uint32	push_time;
#endif // endif
	struct wlfc_hanger_item *next;
} wlfc_hanger_item_t;

/** hanger contains packets that have been posted by the dhd to the dongle and are expected back */
typedef struct wlfc_hanger {
	int max_items;
	uint32 pushed;
	uint32 popped;
	uint32 failed_to_push;
	uint32 failed_to_pop;
	uint32 failed_slotfind;
	uint32 slot_pos;
	wlfc_hanger_item_t items[1];
} wlfc_hanger_t;

#define WLFC_HANGER_SIZE(n)	((sizeof(wlfc_hanger_t) - \
	sizeof(wlfc_hanger_item_t)) + ((n)*sizeof(wlfc_hanger_item_t)))

#define WLFC_STATE_OPEN		1	/**< remote MAC is able to receive packets */
#define WLFC_STATE_CLOSE	2	/**< remote MAC is in power save mode */

#define WLFC_PSQ_PREC_COUNT		((AC_COUNT + 1) * 2) /**< 2 for each AC traffic and bc/mc */
#define WLFC_AFQ_PREC_COUNT		(AC_COUNT + 1)

#define WLFC_PSQ_LEN			(4096 * 8)

#ifdef BCMDBUS
#define WLFC_FLOWCONTROL_HIWATER	512
#define WLFC_FLOWCONTROL_LOWATER	(WLFC_FLOWCONTROL_HIWATER / 4)
#else
#define WLFC_FLOWCONTROL_HIWATER	((4096 * 8) - 256)
#define WLFC_FLOWCONTROL_LOWATER	256
#endif

#if (WLFC_FLOWCONTROL_HIWATER >= (WLFC_PSQ_LEN - 256))
#undef WLFC_FLOWCONTROL_HIWATER
#define WLFC_FLOWCONTROL_HIWATER	(WLFC_PSQ_LEN - 256)
#undef WLFC_FLOWCONTROL_LOWATER
#define WLFC_FLOWCONTROL_LOWATER	(WLFC_FLOWCONTROL_HIWATER / 4)
#endif // endif

#define WLFC_LOG_BUF_SIZE		(1024*1024)

/** Properties related to a remote MAC entity */
typedef struct wlfc_mac_descriptor {
	uint8 occupied;         /**< if 0, this descriptor is unused and thus can be (re)used */
	uint8 interface_id;
	uint8 iftype;           /**< eg WLC_E_IF_ROLE_STA */
	uint8 state;            /**< eg WLFC_STATE_OPEN */
	uint8 ac_bitmap;        /**< automatic power save delivery (APSD) */
	uint8 requested_credit;
	uint8 requested_packet; /**< unit: [number of packets] */
	uint8 ea[ETHER_ADDR_LEN];

	/** maintain (MAC,AC) based seq count for packets going to the device. As well as bc/mc. */
	uint8 seq[AC_COUNT + 1];
	uint8 generation;       /**< toggles between 0 and 1 */
	struct pktq	psq;    /**< contains both 'delayed' and 'suppressed' packets */
	/** packets at firmware queue */
	struct pktq	afq;
	/** The AC pending bitmap that was reported to the fw at last change */
	uint8 traffic_lastreported_bmp;
	/** The new AC pending bitmap */
	uint8 traffic_pending_bmp;
	/** 1= send on next opportunity */
	uint8 send_tim_signal;
	uint8 mac_handle;          /**< mac handles are assigned by the dongle */
	/** Number of packets at dongle for this entry. */
	int transit_count;
	/** Number of suppression to wait before evict from delayQ */
	int suppr_transit_count;
	/** pkt sent to bus but no bus TX complete yet */
	int onbus_pkts_count;
	/** flag. TRUE when remote MAC is in suppressed state */
	uint8 suppressed;

#ifdef PROP_TXSTATUS_DEBUG
	uint32 dstncredit_sent_packets;
	uint32 dstncredit_acks;
	uint32 opened_ct;
	uint32 closed_ct;
#endif // endif
#ifdef PROPTX_MAXCOUNT
	/** Max Number of packets at dongle for this entry. */
	int transit_maxcount;
#endif /* PROPTX_MAXCOUNT */
	struct wlfc_mac_descriptor* prev;
	struct wlfc_mac_descriptor* next;
} wlfc_mac_descriptor_t;

/** A 'commit' is the hand over of a packet from the host OS layer to the layer below (eg DBUS) */
typedef struct dhd_wlfc_commit_info {
	uint8					needs_hdr;
	uint8					ac_fifo_credit_spent;
	ewlfc_packet_state_t	pkt_type;
	wlfc_mac_descriptor_t*	mac_entry;
	void*					p;
} dhd_wlfc_commit_info_t;

#define WLFC_DECR_SEQCOUNT(entry, prec) do { if (entry->seq[(prec)] == 0) {\
	entry->seq[prec] = 0xff; } else entry->seq[prec]--;} while (0)

#define WLFC_INCR_SEQCOUNT(entry, prec) entry->seq[(prec)]++
#define WLFC_SEQCOUNT(entry, prec) entry->seq[(prec)]

typedef struct athost_wl_stat_counters {
	uint32	pktin;
	uint32	pktout;
	uint32	pkt2bus;
	uint32	pktdropped;
	uint32	tlv_parse_failed;
	uint32	rollback;
	uint32	rollback_failed;
	uint32	delayq_full_error;
	uint32	credit_request_failed;
	uint32	packet_request_failed;
	uint32	mac_update_failed;
	uint32	psmode_update_failed;
	uint32	interface_update_failed;
	uint32	wlfc_header_only_pkt;
	uint32	txstatus_in;
	uint32	d11_suppress;
	uint32	wl_suppress;
	uint32	bad_suppress;
	uint32	pkt_dropped;
	uint32	pkt_exptime;
	uint32	pkt_freed;
	uint32	pkt_free_err;
	uint32	psq_wlsup_retx;
	uint32	psq_wlsup_enq;
	uint32	psq_d11sup_retx;
	uint32	psq_d11sup_enq;
	uint32	psq_hostq_retx;
	uint32	psq_hostq_enq;
	uint32	mac_handle_notfound;
	uint32	wlc_tossed_pkts;
	uint32	dhd_hdrpulls;
	uint32	generic_error;
	/* an extra one for bc/mc traffic */
	uint32	send_pkts[AC_COUNT + 1];
	uint32	drop_pkts[WLFC_PSQ_PREC_COUNT];
	uint32	ooo_pkts[AC_COUNT + 1];
#ifdef PROP_TXSTATUS_DEBUG
	/** all pkt2bus -> txstatus latency accumulated */
	uint32	latency_sample_count;
	uint32	total_status_latency;
	uint32	latency_most_recent;
	int	idx_delta;
	uint32	deltas[10];
	uint32	fifo_credits_sent[6];
	uint32	fifo_credits_back[6];
	uint32	dropped_qfull[6];
	uint32	signal_only_pkts_sent;
	uint32	signal_only_pkts_freed;
#endif // endif
	uint32	cleanup_txq_cnt;
	uint32	cleanup_psq_cnt;
	uint32	cleanup_fw_cnt;
} athost_wl_stat_counters_t;

#ifdef PROP_TXSTATUS_DEBUG
#define WLFC_HOST_FIFO_CREDIT_INC_SENTCTRS(ctx, ac) do { \
	(ctx)->stats.fifo_credits_sent[(ac)]++;} while (0)
#define WLFC_HOST_FIFO_CREDIT_INC_BACKCTRS(ctx, ac) do { \
	(ctx)->stats.fifo_credits_back[(ac)]++;} while (0)
#define WLFC_HOST_FIFO_DROPPEDCTR_INC(ctx, ac) do { \
	(ctx)->stats.dropped_qfull[(ac)]++;} while (0)
#else
#define WLFC_HOST_FIFO_CREDIT_INC_SENTCTRS(ctx, ac) do {} while (0)
#define WLFC_HOST_FIFO_CREDIT_INC_BACKCTRS(ctx, ac) do {} while (0)
#define WLFC_HOST_FIFO_DROPPEDCTR_INC(ctx, ac) do {} while (0)
#endif // endif
#define WLFC_PACKET_BOUND              10
#define WLFC_FCMODE_NONE				0
#define WLFC_FCMODE_IMPLIED_CREDIT		1
#define WLFC_FCMODE_EXPLICIT_CREDIT		2
#define WLFC_ONLY_AMPDU_HOSTREORDER		3

/** Reserved credits ratio when borrowed by hihger priority */
#define WLFC_BORROW_LIMIT_RATIO		4

/** How long to defer borrowing in milliseconds */
#define WLFC_BORROW_DEFER_PERIOD_MS 100

/** How long to defer flow control in milliseconds */
#define WLFC_FC_DEFER_PERIOD_MS 200

/** How long to detect occurance per AC in miliseconds */
#define WLFC_RX_DETECTION_THRESHOLD_MS	100

/** Mask to represent available ACs (note: BC/MC is ignored) */
#define WLFC_AC_MASK 0xF

/** flow control specific information, only 1 instance during driver lifetime */
typedef struct athost_wl_status_info {
	uint8	last_seqid_to_wlc;

	/** OSL handle */
	osl_t *osh;
	/** dhd public struct pointer */
	void *dhdp;

	f_commitpkt_t fcommit;
	void* commit_ctx;

	/** statistics */
	athost_wl_stat_counters_t stats;

	/** incremented on eg receiving a credit map event from the dongle */
	int		Init_FIFO_credit[AC_COUNT + 2];
	/** the additional ones are for bc/mc and ATIM FIFO */
	int		FIFO_credit[AC_COUNT + 2];
	/** Credit borrow counts for each FIFO from each of the other FIFOs */
	int		credits_borrowed[AC_COUNT + 2][AC_COUNT + 2];

	/** packet hanger and MAC->handle lookup table */
	void *hanger;

	struct {
		/** table for individual nodes */
		wlfc_mac_descriptor_t	nodes[WLFC_MAC_DESC_TABLE_SIZE];
		/** table for interfaces */
		wlfc_mac_descriptor_t	interfaces[WLFC_MAX_IFNUM];
		/* OS may send packets to unknown (unassociated) destinations */
		/** A place holder for bc/mc and packets to unknown destinations */
		wlfc_mac_descriptor_t	other;
	} destination_entries;

	wlfc_mac_descriptor_t *active_entry_head; /**< a chain of MAC descriptors */
	int active_entry_count;

	wlfc_mac_descriptor_t *requested_entry[WLFC_MAC_DESC_TABLE_SIZE];
	int requested_entry_count;

	/* pkt counts for each interface and ac */
	int	pkt_cnt_in_q[WLFC_MAX_IFNUM][AC_COUNT+1];
	int	pkt_cnt_per_ac[AC_COUNT+1];
	int	pkt_cnt_in_drv[WLFC_MAX_IFNUM][AC_COUNT+1];
	int	pkt_cnt_in_psq;
	uint8	allow_fc;              /**< Boolean */
	uint32  fc_defer_timestamp;
	uint32	rx_timestamp[AC_COUNT+1];

	/** ON/OFF state for flow control to the host network interface */
	uint8	hostif_flow_state[WLFC_MAX_IFNUM];
	uint8	host_ifidx;

	/** to flow control an OS interface */
	uint8	toggle_host_if;

	/** To borrow credits */
	uint8   allow_credit_borrow;

	/** ac number for the first single ac traffic */
	uint8	single_ac;

	/** Timestamp for the first single ac traffic */
	uint32  single_ac_timestamp;

	bool	bcmc_credit_supported;

} athost_wl_status_info_t;

/** Please be mindful that total pkttag space is 32 octets only */
typedef struct dhd_pkttag {

#ifdef BCM_OBJECT_TRACE
	/* if use this field, keep it at the first 4 bytes */
	uint32 sn;
#endif /* BCM_OBJECT_TRACE */

	/**
	b[15]  - 1 = wlfc packet
	b[14:13]  - encryption exemption
	b[12 ] - 1 = event channel
	b[11 ] - 1 = this packet was sent in response to one time packet request,
	do not increment credit on status for this one. [WLFC_CTL_TYPE_MAC_REQUEST_PACKET].
	b[10 ] - 1 = signal-only-packet to firmware [i.e. nothing to piggyback on]
	b[9  ] - 1 = packet is host->firmware (transmit direction)
	       - 0 = packet received from firmware (firmware->host)
	b[8  ] - 1 = packet was sent due to credit_request (pspoll),
	             packet does not count against FIFO credit.
	       - 0 = normal transaction, packet counts against FIFO credit
	b[7  ] - 1 = AP, 0 = STA
	b[6:4] - AC FIFO number
	b[3:0] - interface index
	*/
	uint16	if_flags;

	/**
	 * destination MAC address for this packet so that not every module needs to open the packet
	 * to find this
	 */
	uint8	dstn_ether[ETHER_ADDR_LEN];

	/** This 32-bit goes from host to device for every packet. */
	uint32	htod_tag;

	/** This 16-bit is original d11seq number for every suppressed packet. */
	uint16	htod_seq;

	/** This address is mac entry for every packet. */
	void *entry;

	/** bus specific stuff */
	union {
		struct {
			void *stuff;
			uint32 thing1;
			uint32 thing2;
		} sd;

		struct {
			void *bus;
			void *urb;
		} usb;
	} bus_specific;
} dhd_pkttag_t;

#define DHD_PKTTAG_WLFCPKT_MASK			0x1
#define DHD_PKTTAG_WLFCPKT_SHIFT		15
#define DHD_PKTTAG_WLFCPKT_SET(tag, value)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_WLFCPKT_MASK << DHD_PKTTAG_WLFCPKT_SHIFT)) | \
	(((value) & DHD_PKTTAG_WLFCPKT_MASK) << DHD_PKTTAG_WLFCPKT_SHIFT)
#define DHD_PKTTAG_WLFCPKT(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_WLFCPKT_SHIFT) & DHD_PKTTAG_WLFCPKT_MASK)

#define DHD_PKTTAG_EXEMPT_MASK			0x3
#define DHD_PKTTAG_EXEMPT_SHIFT			13
#define DHD_PKTTAG_EXEMPT_SET(tag, value)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_EXEMPT_MASK << DHD_PKTTAG_EXEMPT_SHIFT)) | \
	(((value) & DHD_PKTTAG_EXEMPT_MASK) << DHD_PKTTAG_EXEMPT_SHIFT)
#define DHD_PKTTAG_EXEMPT(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_EXEMPT_SHIFT) & DHD_PKTTAG_EXEMPT_MASK)

#define DHD_PKTTAG_EVENT_MASK			0x1
#define DHD_PKTTAG_EVENT_SHIFT			12
#define DHD_PKTTAG_SETEVENT(tag, event)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_EVENT_MASK << DHD_PKTTAG_EVENT_SHIFT)) | \
	(((event) & DHD_PKTTAG_EVENT_MASK) << DHD_PKTTAG_EVENT_SHIFT)
#define DHD_PKTTAG_EVENT(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_EVENT_SHIFT) & DHD_PKTTAG_EVENT_MASK)

#define DHD_PKTTAG_ONETIMEPKTRQST_MASK		0x1
#define DHD_PKTTAG_ONETIMEPKTRQST_SHIFT		11
#define DHD_PKTTAG_SETONETIMEPKTRQST(tag)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_ONETIMEPKTRQST_MASK << DHD_PKTTAG_ONETIMEPKTRQST_SHIFT)) | \
	(1 << DHD_PKTTAG_ONETIMEPKTRQST_SHIFT)
#define DHD_PKTTAG_ONETIMEPKTRQST(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_ONETIMEPKTRQST_SHIFT) & DHD_PKTTAG_ONETIMEPKTRQST_MASK)

#define DHD_PKTTAG_SIGNALONLY_MASK		0x1
#define DHD_PKTTAG_SIGNALONLY_SHIFT		10
#define DHD_PKTTAG_SETSIGNALONLY(tag, signalonly)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_SIGNALONLY_MASK << DHD_PKTTAG_SIGNALONLY_SHIFT)) | \
	(((signalonly) & DHD_PKTTAG_SIGNALONLY_MASK) << DHD_PKTTAG_SIGNALONLY_SHIFT)
#define DHD_PKTTAG_SIGNALONLY(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_SIGNALONLY_SHIFT) & DHD_PKTTAG_SIGNALONLY_MASK)

#define DHD_PKTTAG_PKTDIR_MASK			0x1
#define DHD_PKTTAG_PKTDIR_SHIFT			9
#define DHD_PKTTAG_SETPKTDIR(tag, dir)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_PKTDIR_MASK << DHD_PKTTAG_PKTDIR_SHIFT)) | \
	(((dir) & DHD_PKTTAG_PKTDIR_MASK) << DHD_PKTTAG_PKTDIR_SHIFT)
#define DHD_PKTTAG_PKTDIR(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_PKTDIR_SHIFT) & DHD_PKTTAG_PKTDIR_MASK)

#define DHD_PKTTAG_CREDITCHECK_MASK		0x1
#define DHD_PKTTAG_CREDITCHECK_SHIFT		8
#define DHD_PKTTAG_SETCREDITCHECK(tag, check)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_CREDITCHECK_MASK << DHD_PKTTAG_CREDITCHECK_SHIFT)) | \
	(((check) & DHD_PKTTAG_CREDITCHECK_MASK) << DHD_PKTTAG_CREDITCHECK_SHIFT)
#define DHD_PKTTAG_CREDITCHECK(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_CREDITCHECK_SHIFT) & DHD_PKTTAG_CREDITCHECK_MASK)

#define DHD_PKTTAG_IFTYPE_MASK			0x1
#define DHD_PKTTAG_IFTYPE_SHIFT			7
#define DHD_PKTTAG_SETIFTYPE(tag, isAP)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & \
	~(DHD_PKTTAG_IFTYPE_MASK << DHD_PKTTAG_IFTYPE_SHIFT)) | \
	(((isAP) & DHD_PKTTAG_IFTYPE_MASK) << DHD_PKTTAG_IFTYPE_SHIFT)
#define DHD_PKTTAG_IFTYPE(tag)	((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_IFTYPE_SHIFT) & DHD_PKTTAG_IFTYPE_MASK)

#define DHD_PKTTAG_FIFO_MASK			0x7
#define DHD_PKTTAG_FIFO_SHIFT			4
#define DHD_PKTTAG_SETFIFO(tag, fifo)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & ~(DHD_PKTTAG_FIFO_MASK << DHD_PKTTAG_FIFO_SHIFT)) | \
	(((fifo) & DHD_PKTTAG_FIFO_MASK) << DHD_PKTTAG_FIFO_SHIFT)
#define DHD_PKTTAG_FIFO(tag)		((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_FIFO_SHIFT) & DHD_PKTTAG_FIFO_MASK)

#define DHD_PKTTAG_IF_MASK			0xf
#define DHD_PKTTAG_IF_SHIFT			0
#define DHD_PKTTAG_SETIF(tag, if)	((dhd_pkttag_t*)(tag))->if_flags = \
	(((dhd_pkttag_t*)(tag))->if_flags & ~(DHD_PKTTAG_IF_MASK << DHD_PKTTAG_IF_SHIFT)) | \
	(((if) & DHD_PKTTAG_IF_MASK) << DHD_PKTTAG_IF_SHIFT)
#define DHD_PKTTAG_IF(tag)		((((dhd_pkttag_t*)(tag))->if_flags >> \
	DHD_PKTTAG_IF_SHIFT) & DHD_PKTTAG_IF_MASK)

#define DHD_PKTTAG_SETDSTN(tag, dstn_MAC_ea)	memcpy(((dhd_pkttag_t*)((tag)))->dstn_ether, \
	(dstn_MAC_ea), ETHER_ADDR_LEN)
#define DHD_PKTTAG_DSTN(tag)	((dhd_pkttag_t*)(tag))->dstn_ether

#define DHD_PKTTAG_SET_H2DTAG(tag, h2dvalue)	((dhd_pkttag_t*)(tag))->htod_tag = (h2dvalue)
#define DHD_PKTTAG_H2DTAG(tag)			(((dhd_pkttag_t*)(tag))->htod_tag)

#define DHD_PKTTAG_SET_H2DSEQ(tag, seq)		((dhd_pkttag_t*)(tag))->htod_seq = (seq)
#define DHD_PKTTAG_H2DSEQ(tag)			(((dhd_pkttag_t*)(tag))->htod_seq)

#define DHD_PKTTAG_SET_ENTRY(tag, entry)	((dhd_pkttag_t*)(tag))->entry = (entry)
#define DHD_PKTTAG_ENTRY(tag)			(((dhd_pkttag_t*)(tag))->entry)

#define PSQ_SUP_IDX(x) (x * 2 + 1)
#define PSQ_DLY_IDX(x) (x * 2)

#ifdef PROP_TXSTATUS_DEBUG
#define DHD_WLFC_CTRINC_MAC_CLOSE(entry)	do { (entry)->closed_ct++; } while (0)
#define DHD_WLFC_CTRINC_MAC_OPEN(entry)		do { (entry)->opened_ct++; } while (0)
#else
#define DHD_WLFC_CTRINC_MAC_CLOSE(entry)	do {} while (0)
#define DHD_WLFC_CTRINC_MAC_OPEN(entry)		do {} while (0)
#endif // endif

#ifdef BCM_OBJECT_TRACE
#define DHD_PKTTAG_SET_SN(tag, val)		((dhd_pkttag_t*)(tag))->sn = (val)
#define DHD_PKTTAG_SN(tag)			(((dhd_pkttag_t*)(tag))->sn)
#endif /* BCM_OBJECT_TRACE */

/* public functions */
int dhd_wlfc_parse_header_info(dhd_pub_t *dhd, void* pktbuf, int tlv_hdr_len,
	uchar *reorder_info_buf, uint *reorder_info_len);
KERNEL_THREAD_RETURN_TYPE dhd_wlfc_transfer_packets(void *data);
int dhd_wlfc_commit_packets(dhd_pub_t *dhdp, f_commitpkt_t fcommit,
	void* commit_ctx, void *pktbuf, bool need_toggle_host_if);
int dhd_wlfc_txcomplete(dhd_pub_t *dhd, void *txp, bool success);
int dhd_wlfc_init(dhd_pub_t *dhd);
#ifdef SUPPORT_P2P_GO_PS
int dhd_wlfc_suspend(dhd_pub_t *dhd);
int dhd_wlfc_resume(dhd_pub_t *dhd);
#endif /* SUPPORT_P2P_GO_PS */
int dhd_wlfc_hostreorder_init(dhd_pub_t *dhd);
int dhd_wlfc_cleanup_txq(dhd_pub_t *dhd, f_processpkt_t fn, void *arg);
int dhd_wlfc_cleanup(dhd_pub_t *dhd, f_processpkt_t fn, void* arg);
int dhd_wlfc_deinit(dhd_pub_t *dhd);
int dhd_wlfc_interface_event(dhd_pub_t *dhdp, uint8 action, uint8 ifid, uint8 iftype, uint8* ea);
int dhd_wlfc_FIFOcreditmap_event(dhd_pub_t *dhdp, uint8* event_data);
#ifdef LIMIT_BORROW
int dhd_wlfc_disable_credit_borrow_event(dhd_pub_t *dhdp, uint8* event_data);
#endif /* LIMIT_BORROW */
int dhd_wlfc_BCMCCredit_support_event(dhd_pub_t *dhdp);
int dhd_wlfc_enable(dhd_pub_t *dhdp);
int dhd_wlfc_dump(dhd_pub_t *dhdp, struct bcmstrbuf *strbuf);
int dhd_wlfc_clear_counts(dhd_pub_t *dhd);
int dhd_wlfc_get_enable(dhd_pub_t *dhd, bool *val);
int dhd_wlfc_get_mode(dhd_pub_t *dhd, int *val);
int dhd_wlfc_set_mode(dhd_pub_t *dhd, int val);
bool dhd_wlfc_is_supported(dhd_pub_t *dhd);
bool dhd_wlfc_is_header_only_pkt(dhd_pub_t * dhd, void *pktbuf);
int dhd_wlfc_flowcontrol(dhd_pub_t *dhdp, bool state, bool bAcquireLock);
int dhd_wlfc_save_rxpath_ac_time(dhd_pub_t * dhd, uint8 prio);

int dhd_wlfc_get_module_ignore(dhd_pub_t *dhd, int *val);
int dhd_wlfc_set_module_ignore(dhd_pub_t *dhd, int val);
int dhd_wlfc_get_credit_ignore(dhd_pub_t *dhd, int *val);
int dhd_wlfc_set_credit_ignore(dhd_pub_t *dhd, int val);
int dhd_wlfc_get_txstatus_ignore(dhd_pub_t *dhd, int *val);
int dhd_wlfc_set_txstatus_ignore(dhd_pub_t *dhd, int val);

int dhd_wlfc_get_rxpkt_chk(dhd_pub_t *dhd, int *val);
int dhd_wlfc_set_rxpkt_chk(dhd_pub_t *dhd, int val);
#ifdef PROPTX_MAXCOUNT
int dhd_wlfc_update_maxcount(dhd_pub_t *dhdp, uint8 ifid, int maxcount);
#endif /* PROPTX_MAXCOUNT */

#endif /* __wlfc_host_driver_definitions_h__ */
