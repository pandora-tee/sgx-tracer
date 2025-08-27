#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include "sgx-defs.h"
#include <string.h>

#ifdef IN_KERNEL_DRV
    #include <asm/sgx.h>
#else
    #ifdef ISGX_DRV
        #warning compiling for out-of-tree /dev/isgx driver
        #include "sgx_user.h"
    #else
        #error unsupported SGX driver
    #endif
#endif

#define SYS_EXIT    231
#define SYS_IOCTL   16
#define SYS_ACCESS  21
#define SYS_OPEN    2

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)

#define ASSERT_RV(fct)                                                  \
    ASSERT((fct) != -1)

#define ASSERT_PTRACE(fct)                                              \
    if (fct == -1)                                                      \
    {                                                                   \
        if (errno == ESRCH)                                             \
        {                                                               \
            printf("\n\nTracee exited. Exiting myself.\n");             \
            goto exit;                                                  \
        } else {                                                        \
            perror("[" __FILE__ "] ptrace '" #fct "' failed");          \
            abort();                                                    \
        }                                                               \
    }

// dump file related variables
#define MAX_STRING_BUFFER 100
#define MAX_FDS 10
FILE* json_fds[MAX_FDS];
int fds[MAX_FDS]; // our FDs
uint64_t encountered_fds[MAX_FDS]; // FDs seen in ptrace logs
enum json_types {JSON_TYPE_SECS, JSON_TYPE_TCS, JSON_TYPE_PAGE};


void dump_hex(uint8_t *buf, int len)
{
    for (int i=0; i < len; i++)
        printf("%02x", *(buf + i));
    printf("\n");
}

void open_dumpfile(uint64_t fd_index)
{   
    int fd = fds[fd_index];
    if (fd == -1)
    {
        char filename[MAX_STRING_BUFFER];
        snprintf (filename, sizeof(filename), "enclave%lu.dump", fd_index);
        ASSERT( (fd = open(filename, O_RDWR|O_CREAT|O_TRUNC,
                    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) >= 0 );
        fds[fd_index] = fd;
    }
}

void dump_file(int fd, size_t offset, void *buf, size_t len)
{    
    ASSERT( pwrite(fd, buf, len, offset) == len);
}

void close_dumpfile(uint64_t fd_index)
{
    int fd = fds[fd_index];
    if (fd != -1)
    {
        fsync(fd);
        close(fd);
        fds[fd_index] = -1;
    }
}

void open_json(uint64_t fd_index)
{
    char filename[MAX_STRING_BUFFER];
    snprintf (filename, sizeof(filename), "enclave%lu.json", fd_index);
    FILE* json_fd = json_fds[fd_index];
    if (json_fd == NULL)
    {
        ASSERT( (json_fd = fopen(filename, "w+")) >= 0 );
        json_fds[fd_index] = json_fd;
        fprintf(json_fd, "[\n");
    }
    
}

void close_json(uint64_t fd_index)
{   
    FILE* json_fd = json_fds[fd_index];
    if (json_fd != NULL)
    {
        fprintf(json_fd, "]\n");
        fclose(json_fd);
        json_fds[fd_index] = NULL;
    }
}

void read_mem_pid(pid_t pid, void* buf, uint64_t addr, size_t len)
{
    const struct iovec local_iov = {
        .iov_base = buf,
        .iov_len = len,
    };
    const struct iovec remote_iov = {
        .iov_base = (void*) addr,
        .iov_len = len,
    };

    ASSERT_RV(process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0));
}

void json_write_secs(FILE* json_fd, struct sgx_secs* secs)
{
    fprintf(json_fd,
        "{"
        "\"entry_type\": %d,\n"
        "\"size\": %lu,\n"
        "\"base\": %lu,\n"
        "\"ssa_frame_size\": %u,\n"
        "\"miscselect\": %u,\n"
        "\"attributes\": %lu,\n"
        "\"xfrm\": %lu\n"
        "}",
        (int) JSON_TYPE_SECS,
        secs->size,
        secs->base,
        secs->ssa_frame_size,
        secs->miscselect,
        secs->attributes,
        secs->xfrm
    );
}

uint64_t encl_base_addr = -1;

FILE *mrenclave_fd = NULL;
void sgxs_append(void *block, size_t len)
{
    if (!mrenclave_fd)
    {
        ASSERT( (mrenclave_fd = fopen("enclave0.sgxs", "w+")) >= 0 );
    }

    ASSERT( write(fileno(mrenclave_fd), block, len) == len);
}

/* https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/sgx.h#L44 */
void enclave_create(uint64_t fd_index, pid_t pid, uint64_t arg)
{
    struct sgx_enclave_create e;
    struct sgx_secs s;
    struct mrenclave_ecreate mrc = {0x0};

    read_mem_pid(pid, &e, arg, sizeof(e));
    printf("\tSGX_IOC_ENCLAVE_CREATE: src=%#llx\n", e.src);

    read_mem_pid(pid, &s, e.src, sizeof(s));
    printf("\tSECS: size=%lu; base=%#lx; ssa_frame_size=%u; miscselect=%u; attributes=%#lx; xfrm=%lu\n",
        s.size, s.base, s.ssa_frame_size, s.miscselect, s.attributes, s.xfrm);
    json_write_secs(json_fds[fd_index], &s);
    encl_base_addr = s.base;

    mrc.tag = MRENCLAVE_TAG_ECREATE;
    mrc.ssaframesize = s.ssa_frame_size;
    mrc.size = s.size;
    sgxs_append(&mrc, sizeof(mrc));
}

/* https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/sgx.h#L72 */
void enclave_init(uint64_t fd_index, pid_t pid, uint64_t arg)
{
    struct sgx_enclave_init i;
    struct sgx_sigstruct s;

    read_mem_pid(pid, &i, arg, sizeof(i));
    printf("\tSGX_IOC_ENCLAVE_INIT: sigstruct=%#llx\n", i.sigstruct);

    read_mem_pid(pid, &s, i.sigstruct, sizeof(s));
    printf("\tMRENCLAVE: ");
    dump_hex((uint8_t*) &s.body.mrenclave, sizeof(s.body.mrenclave));
}

char *get_page_type(int type)
{
    char *page_types[7] = {"PT_SECS", "PT_TCS", "PT_REG", "PT_VA", "PT_TRIM", "PT_SS_FIRST", "PT_SS_REST"};
    if (type < 0 || type >= 7)
        return "RSVD";
    else
        return page_types[type];
}

#ifndef IN_KERNEL_DRV
    #define SGX_IOC_ENCLAVE_ADD_PAGES   SGX_IOC_ENCLAVE_ADD_PAGE
    #define SGX_PAGE_MEASURE            0x01
    struct sgx_enclave_add_pages {
        __u64 src;
        __u64 offset;
        __u64 length;
        __u64 secinfo;
        __u64 flags;
        __u64 count;
    };

    void read_add_pages_struct(pid_t pid, uint64_t arg, struct sgx_enclave_add_pages *res)
    {
        struct sgx_enclave_add_page p;
        read_mem_pid(pid, &p, arg, sizeof(p));
    
        ASSERT( encl_base_addr != -1 );
        /* no support for partial page measurement */
        ASSERT( p.mrmask == 0x0 || p.mrmask == 0xffff);

        res->src = p.src;
        res->offset = p.addr - encl_base_addr;
        res->length = 4096;
        res->secinfo = p.secinfo;
        res->flags = (p.mrmask == 0xffff) ? SGX_PAGE_MEASURE : 0x0;
        res->count = 4096;
    }
#else
    void read_add_pages_struct(pid_t pid, uint64_t arg, struct sgx_enclave_add_pages *res)
    {
        read_mem_pid(pid, res, arg, sizeof(*res));
    }
#endif

void json_write_page(FILE* json_fd, struct sgx_enclave_add_pages* page, const char* perms, char* type)
{
    fprintf(json_fd,
        ",{\n"
        "\"entry_type\": %d,\n"
        "\"src\": %llu,\n"
        "\"offset\": %llu,\n"
        "\"length\": %llu,\n"
        "\"secinfo\": %llu,\n"
        "\"flags\": %llu,\n"
        "\"measured\": %d,\n"
        "\"count\": %llu,\n"
        "\"permissions\": \"%s\",\n"
        "\"type\": \"%s\"\n"
        "}\n",
        (int) JSON_TYPE_PAGE,
        page->src,
        page->offset,
        page->length,
        page->secinfo,
        page->flags,
        (int) (page->flags & SGX_PAGE_MEASURE),
        page->count,
        perms,
        type

    );
}

void json_write_tcs(FILE* json_fd, struct sgx_tcs* tcs)
{
    fprintf(json_fd,
        ",{\n"
        "\"entry_type\": %d,\n"
        "\"state\": %lu,\n"
        "\"flags\": %lu,\n"
        "\"ssa_offset\": %lu,\n"
        "\"ssa_index\": %u,\n"
        "\"ssa_num\": %u,\n"
        "\"entry_offset\": %lu,\n"
        "\"exit_addr\": %lu,\n"
        "\"fs_base\": %lu,\n"
        "\"gs_base\": %lu\n"
        "}\n",
        (int) JSON_TYPE_TCS,
        tcs->state,
        tcs->flags,
        tcs->ssa_offset,
        tcs->ssa_index,
        tcs->nr_ssa_frames,
        tcs->entry_offset,
        tcs->exit_addr,
        tcs->fs_offset,
        tcs->gs_offset
    );
}

/* https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/sgx.h#L58 */
void enclave_add_pages(uint64_t fd_index, pid_t pid, uint64_t arg)
{
    struct sgx_enclave_add_pages p;
    struct sgx_secinfo s;
    char r, w, x;
    int type, measure;
    uint8_t *page = NULL;
    struct mrenclave_eadd mra = {0x0};
    struct mrenclave_eextend mre = {0x0};

    read_add_pages_struct(pid, arg, &p);
    read_mem_pid(pid, &s, p.secinfo, sizeof(s));
    measure = (int) (p.flags & SGX_PAGE_MEASURE);
    printf("\tSGX_IOC_ENCLAVE_ADD_PAGES: src=%#llx; offset=%#llx; "
           "len=%llu; secinfo=%#lx; measure=%d; count=%llu\n",
            p.src, p.offset, p.length, s.flags, measure, p.count);

    r = s.flags & (0x1 << 0) ? 'R' : '-';
    w = s.flags & (0x1 << 1) ? 'W' : '-';
    x = s.flags & (0x1 << 2) ? 'X' : '-';
    type = s.flags >> 8;
    char* page_type = get_page_type(type);
    char perms[] = {r, w, x, '\0'};
    printf("\tSECINFO: perms=%s; type=%s\n", perms, page_type);
    json_write_page(json_fds[fd_index], &p, perms, page_type);

    if (type == 1)
    {
        struct sgx_tcs tcs;
        read_mem_pid(pid, &tcs, p.src, sizeof(tcs));
        printf("\tTCS: state=%#lx; flags=%#lx; ssa_offset=%lx; ssa_index=%u; ssa_nr=%u; "
               "entry_offset=%#lx; exit_addr=%#lx;\n"
               "\t     fs_offset=%#lx; gs_offset=%#lx; fs_limit=%#x; gs_limit=%#x\n",
                tcs.state, tcs.flags, tcs.ssa_offset, tcs.ssa_index, tcs.nr_ssa_frames,
                tcs.entry_offset, tcs.exit_addr, tcs.fs_offset, tcs.gs_offset,
                tcs.fs_limit, tcs.gs_limit);
        json_write_tcs(json_fds[fd_index], &tcs);
    }

    ASSERT( p.length != 0 );
    page = malloc(p.length);
    ASSERT( page != NULL );
    read_mem_pid(pid, page, p.src, p.length);
    dump_file(fds[fd_index], p.offset, page, p.length);
    //printf("\tPAGE DUMP: ");
    //dump_hex((uint8_t*) page, num_bytes);


    for (int j = 0; j < p.length; j += 4096)
    {
        mra.tag = MRENCLAVE_TAG_EADD;
        mra.offset = p.offset + j;
        memcpy(&mra.secinfo, &s, sizeof(mra.secinfo));
        sgxs_append(&mra, sizeof(mra));

        if (measure)
        {
            for (int i = 0; i < 4096; i += 256)
            {
                mre.tag = MRENCLAVE_TAG_EEXTEND;
                mre.offset = p.offset + j + i;
                memcpy(mre.blob, page + j + i, sizeof(mre.blob));
                sgxs_append(&mre, sizeof(mre));
            }
        }
    }

    free(page);
}

int main(int argc, char **argv)
{
    pid_t pid;
    struct user_regs_struct regs;
    uint64_t sys, fd, arg;
    uint32_t cmd;
    uint64_t file_addr, mode, data;

    ASSERT(argc > 1);
    ASSERT_RV(pid = fork());

    /* child */
    if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], argv + 1);
        ASSERT(0 && "child exec failed");
    }

    /* parent */

    // prepare file descriptor arrays
    for (int i = 0; i<MAX_FDS; i++)
    {
        fds[i] = -1;
        json_fds[i] = NULL;
        encountered_fds[i] = 0;
    }

    // Set ptrace options
    ASSERT_RV(waitpid(pid, 0, 0));
    ASSERT_PTRACE(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL));

    printf("ioctl SGX calls are:\nCREATE:%#lx\nADD:%#lx\nINIT:%#lx\n", SGX_IOC_ENCLAVE_CREATE, SGX_IOC_ENCLAVE_ADD_PAGES, SGX_IOC_ENCLAVE_INIT);

    // Start listening
    while(1)
    {
        /* Wait for next system call in child */
    	ASSERT_PTRACE(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        ASSERT_RV(waitpid(pid, 0, 0));

        /* Print arguments */
        ASSERT_PTRACE(ptrace(PTRACE_GETREGS, pid, 0, &regs));
        if ((sys = regs.orig_rax) == SYS_IOCTL)
        {
            fd = regs.rdi;
            cmd = regs.rsi;
            arg = regs.rdx;
            printf("[%lu] ioctl(%lu, %#x, %#lx)\n", sys, fd, cmd, arg);
        }

        // only on IOCTL, we continue with this loop (and break the switch)
        // We ignore all other syscalls and go to next loop iteration
        if (sys == SYS_IOCTL)
        {
            /* Check the FD and open a file for it if we don't have it yet */
            int fd_index = -1;
            for (int i = 0; i < MAX_FDS ; i++)
            {
                if (encountered_fds[i] == fd){
                    fd_index = i;
                    break;
                }
            }
    
            /* https://www.kernel.org/doc/html/latest/x86/sgx.html#application-interface */
            switch (cmd)
            {
            case SGX_IOC_ENCLAVE_CREATE:
                // On ENCLAVE_CREATE, open a new FD for this enclave.
                if (fd_index < 0)
                {
                    // Attempt to find an empty array slot
                    for (int i = 0; i < MAX_FDS ; i++)
                    {
                        if (encountered_fds[i] == 0)
                        {
                            // Got one that's empty. Open files and remember it.
                            fd_index = i;
                            printf("Encountered new ioctl on FD %lu. Opening new enclave dump at index %d.\n", fd, fd_index);
                            encountered_fds[i] = fd;
                            open_dumpfile(fd_index);
                            open_json(fd_index);
                            break;
                        }
                    }
                    // If we still don't have an fd index, we're out of luck and have to abort.
                    if (fd_index < 0)
                    {
                        perror("Ran out of file descriptors, this program created too many enclaves!\n");
                        abort();
                    }
                } else {
                    perror("ENCLAVE CREATE but already had a FD for this. aborting.");
                    abort();
                }
    
                enclave_create(fd_index, pid, arg);
                break;
            case SGX_IOC_ENCLAVE_ADD_PAGES:
                enclave_add_pages(fd_index, pid, arg);
                break;
            case SGX_IOC_ENCLAVE_INIT:
                enclave_init(fd_index, pid, arg);
                printf("closing initialized enclave dump on FD %lu\n", fd);
                close_json(fd_index);
                close_dumpfile(fd_index);
		fclose(mrenclave_fd);
                break;        
            default:
                printf("UNKNOWN IOC (probably not SGX-related, ignoring..)\n");
                break;
            }
	}

        /* Execute system call */
        ASSERT_PTRACE(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        ASSERT_RV(waitpid(pid, 0, 0));

        /* Check exit(2) or similar */
        ASSERT_PTRACE(ptrace(PTRACE_GETREGS, pid, 0, &regs));
	if (errno == ESRCH )
	    goto exit;
    }
    return 1;

    exit:
        ;
        int num = 0;
        for (int i=0; i<MAX_FDS;i++)
        {
            if ((fds[i] != -1) || (json_fds[i] != NULL))
            {
                printf("WARNING: uninitialized enclave with fd=%d\n", i);
                num++;
                close_json(i);
                close_dumpfile(i);
            }
        }
        if (num > 0)
        {
            printf("WARNING: %d uninitialized enclaves on exit\n", num);
            return 1;
        }
        printf("all is well; exiting gracefully..\n");
        return 0;
}
