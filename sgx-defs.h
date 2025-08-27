#ifndef SGX_DEFS_H_INC
#define SGX_DEFS_H_INC

/*
 * Architectural definitions of SGX structures, as defined in Intel SDM and
 * copied from Linux kernel.
 */

#pragma pack(1)

/* https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/sgx.h#L291 */
/**
 * struct sgx_secs - SGX Enclave Control Structure (SECS)
 * @size:		size of the address space
 * @base:		base address of the  address space
 * @ssa_frame_size:	size of an SSA frame
 * @miscselect:		additional information stored to an SSA frame
 * @attributes:		attributes for enclave
 * @xfrm:		XSave-Feature Request Mask (subset of XCR0)
 * @mrenclave:		SHA256-hash of the enclave contents
 * @mrsigner:		SHA256-hash of the public key used to sign the SIGSTRUCT
 * @config_id:		a user-defined value that is used in key derivation
 * @isv_prod_id:	a user-defined value that is used in key derivation
 * @isv_svn:		a user-defined value that is used in key derivation
 * @config_svn:		a user-defined value that is used in key derivation
 *
 * SGX Enclave Control Structure (SECS) is a special enclave page that is not
 * visible in the address space. In fact, this structure defines the address
 * range and other global attributes for the enclave and it is the first EPC
 * page created for any enclave. It is moved from a temporary buffer to an EPC
 * by the means of ENCLS[ECREATE] function.
 */
struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssa_frame_size;
	uint32_t miscselect;
	uint8_t  reserved1[24];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t  reserved2[32];
	uint32_t mrsigner[8];
	uint8_t  reserved3[32];
	uint32_t config_id[16];
	uint16_t isv_prod_id;
	uint16_t isv_svn;
	uint16_t config_svn;
	uint8_t  reserved4[3834];
};

/**
 * struct sgx_secinfo - describes attributes of an EPC page
 * @flags:	permissions and type
 *
 * Used together with ENCLS leaves that add or modify an EPC page to an
 * enclave to define page permissions and type.
 */
struct sgx_secinfo {
	uint64_t flags;
	uint8_t  reserved[56];
};

/**
 * struct sgx_tcs - Thread Control Structure (TCS)
 * @state:		used to mark an entered TCS
 * @flags:		execution flags (cleared by EADD)
 * @ssa_offset:		SSA stack offset relative to the enclave base
 * @ssa_index:		the current SSA frame index (cleard by EADD)
 * @nr_ssa_frames:	the number of frame in the SSA stack
 * @entry_offset:	entry point offset relative to the enclave base
 * @exit_addr:		address outside the enclave to exit on an exception or
 *			interrupt
 * @fs_offset:		offset relative to the enclave base to become FS
 *			segment inside the enclave
 * @gs_offset:		offset relative to the enclave base to become GS
 *			segment inside the enclave
 * @fs_limit:		size to become a new FS-limit (only 32-bit enclaves)
 * @gs_limit:		size to become a new GS-limit (only 32-bit enclaves)
 *
 * Thread Control Structure (TCS) is an enclave page visible in its address
 * space that defines an entry point inside the enclave. A thread enters inside
 * an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
 * by only one thread at a time.
 */
struct sgx_tcs {
	uint64_t state;
	uint64_t flags;
	uint64_t ssa_offset;
	uint32_t ssa_index;
	uint32_t nr_ssa_frames;
	uint64_t entry_offset;
	uint64_t exit_addr;
	uint64_t fs_offset;
	uint64_t gs_offset;
	uint32_t fs_limit;
	uint32_t gs_limit;
	uint8_t  reserved[4024];
};

/**
 * struct sgx_sigstruct_header -  defines author of the enclave
 * @header1:		constant byte string
 * @vendor:		must be either 0x0000 or 0x8086
 * @date:		YYYYMMDD in BCD
 * @header2:		constant byte string
 * @swdefined:		software defined value
 */
struct sgx_sigstruct_header {
	uint64_t header1[2];
	uint32_t vendor;
	uint32_t date;
	uint64_t header2[2];
	uint32_t swdefined;
	uint8_t  reserved1[84];
};

/**
 * struct sgx_sigstruct_body - defines contents of the enclave
 * @miscselect:		additional information stored to an SSA frame
 * @misc_mask:		required miscselect in SECS
 * @attributes:		attributes for enclave
 * @xfrm:		XSave-Feature Request Mask (subset of XCR0)
 * @attributes_mask:	required attributes in SECS
 * @xfrm_mask:		required XFRM in SECS
 * @mrenclave:		SHA256-hash of the enclave contents
 * @isvprodid:		a user-defined value that is used in key derivation
 * @isvsvn:		a user-defined value that is used in key derivation
 */
struct sgx_sigstruct_body {
	uint32_t miscselect;
	uint32_t misc_mask;
	uint8_t  reserved2[20];
	uint64_t attributes;
	uint64_t xfrm;
	uint64_t attributes_mask;
	uint64_t xfrm_mask;
	uint8_t  mrenclave[32];
	uint8_t  reserved3[32];
	uint16_t isvprodid;
	uint16_t isvsvn;
};

/* The modulus size for 3072-bit RSA keys. */
#define SGX_MODULUS_SIZE 384

/**
 * struct sgx_sigstruct - an enclave signature
 * @header:		defines author of the enclave
 * @modulus:		the modulus of the public key
 * @exponent:		the exponent of the public key
 * @signature:		the signature calculated over the fields except modulus,
 * @body:		defines contents of the enclave
 * @q1:			a value used in RSA signature verification
 * @q2:			a value used in RSA signature verification
 *
 * Header and body are the parts that are actual signed. The remaining fields
 * define the signature of the enclave.
 */
struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	uint8_t  modulus[SGX_MODULUS_SIZE];
	uint32_t exponent;
	uint8_t  signature[SGX_MODULUS_SIZE];
	struct sgx_sigstruct_body body;
	uint8_t  reserved4[12];
	uint8_t  q1[SGX_MODULUS_SIZE];
	uint8_t  q2[SGX_MODULUS_SIZE];
};


/*
 * MRENCLAVE blocks as defined in Intel SDM.
 */

#define MRENCLAVE_TAG_ECREATE	0x0045544145524345 // "ECREATE\0"
#define MRENCLAVE_TAG_EADD	0x0000000044444145 // "EADD\0\0\0\0"
#define MRENCLAVE_TAG_EEXTEND   0x00444E4554584545 // "EEXTEND\0"

struct mrenclave_ecreate {
	uint64_t tag;
	uint32_t ssaframesize;
	uint64_t size;
	uint8_t  rsvd[44];
};
_Static_assert(sizeof(struct mrenclave_ecreate) == 64, "MRENCLAVE block size");

struct mrenclave_eadd {
	uint64_t tag;
	uint64_t offset;
	uint8_t  secinfo[48];
};
_Static_assert(sizeof(struct mrenclave_eadd) == 64, "MRENCLAVE block size");

struct mrenclave_eextend {
	uint64_t tag;
	uint64_t offset;
	uint8_t  zeroes[48];
        uint8_t  blob[256];
};
_Static_assert(sizeof(struct mrenclave_eextend) == 5*64, "MRENCLAVE block size");





#endif
