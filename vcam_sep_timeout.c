// vcam_sep_timeout.c — 5s recv timeout on SEP socket (127.0.0.1:1789)
// Self-contained: constructor + dlsym + raw GOT patch, no external deps
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdlib.h>

static const in_port_t SEP_PORT = 1789;

static int      (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t  (*orig_recv)(int, void *, size_t, int);

static int is_sep_socket(int fd) {
    struct sockaddr_in sin; socklen_t l = sizeof(sin);
    if (getpeername(fd, (struct sockaddr *)&sin, &l) != 0) return 0;
    return sin.sin_family == AF_INET &&
           sin.sin_port   == htons(SEP_PORT) &&
           sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
}

static int hooked_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (sin->sin_family == AF_INET &&
            sin->sin_port == htons(SEP_PORT) &&
            sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            struct timeval tv = {5, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
    }
    return orig_connect(fd, addr, len);
}

static ssize_t hooked_recv(int fd, void *buf, size_t n, int flags) {
    ssize_t r = orig_recv(fd, buf, n, flags);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && is_sep_socket(fd))
        errno = ETIMEDOUT;
    return r;
}

// Minimal GOT/PLT rebind for a single symbol
static void *find_symbol(const char *name) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        Dl_info info;
        if (dladdr(hdr, &info) == 0) continue;

        uintptr_t cur = (uintptr_t)hdr + (hdr->magic == MH_MAGIC_64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
        struct symtab_command *symtab = NULL;
        struct dysymtab_command *dysymtab = NULL;
        uintptr_t linkedit_base = 0;

        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            struct load_command *lc = (struct load_command *)cur;
            if (lc->cmd == LC_SYMTAB) symtab = (struct symtab_command *)lc;
            if (lc->cmd == LC_DYSYMTAB) dysymtab = (struct dysymtab_command *)lc;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__LINKEDIT") == 0)
                    linkedit_base = slide + seg->vmaddr - seg->fileoff;
            }
            cur += lc->cmdsize;
        }
        if (!symtab || !dysymtab || !linkedit_base) continue;

        struct nlist_64 *sym = (struct nlist_64 *)(linkedit_base + symtab->symoff);
        char *strtab = (char *)(linkedit_base + symtab->stroff);
        uint32_t *indirect = (uint32_t *)(linkedit_base + dysymtab->indirectsymoff);

        cur = (uintptr_t)hdr + (hdr->magic == MH_MAGIC_64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            struct load_command *lc = (struct load_command *)cur;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                struct section_64 *sect = (struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64));
                for (uint32_t k = 0; k < seg->nsects; k++) {
                    if ((sect[k].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                        (sect[k].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                        uint32_t *indices = indirect + sect[k].reserved1;
                        void **ptrs = (void **)(slide + sect[k].addr);
                        for (uint32_t m = 0; m < sect[k].size / sizeof(void *); m++) {
                            uint32_t idx = indices[m];
                            if (idx == INDIRECT_SYMBOL_ABS || idx == INDIRECT_SYMBOL_LOCAL) continue;
                            if (strcmp(strtab + sym[idx].n_un.n_strx, name) == 0)
                                return ptrs[m];  // Found the stub pointer
                        }
                    }
                }
            }
            cur += lc->cmdsize;
        }
    }
    return NULL;
}

__attribute__((constructor))
static void init(void) {
    // Get originals
    orig_connect = dlsym(RTLD_NEXT, "connect");
    orig_recv    = dlsym(RTLD_NEXT, "recv");
    if (!orig_connect) orig_connect = dlsym(RTLD_DEFAULT, "connect");
    if (!orig_recv)    orig_recv    = dlsym(RTLD_DEFAULT, "recv");
    if (!orig_connect || !orig_recv) return;

    // Patch GOT/PLT entries
    void **connect_ptr = (void **)find_symbol("connect");
    void **recv_ptr    = (void **)find_symbol("recv");
    if (connect_ptr) *connect_ptr = hooked_connect;
    if (recv_ptr)    *recv_ptr    = hooked_recv;
}
