// sep_timeout.c — self-contained connect/recv GOT rebinder, no external deps.
// xcrun clang -arch arm64 -arch arm64e -dynamiclib \
//   -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//   -miphoneos-version-min=14.0 -o sep_timeout.dylib sep_timeout.c
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#if defined(__arm64e__)
#include <ptrauth.h>
#endif

typedef struct mach_header_64     mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64         section_t;
typedef struct nlist_64           nlist_t;

/* ---------- 5s recv timeout on 127.0.0.1:1789 ---------- */

static const in_port_t SEP_PORT = 1789;
static int      (*real_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t  (*real_recv)(int, void *, size_t, int);
static ssize_t  (*real_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

static int is_sep_socket(int fd) {
    struct sockaddr_in s; socklen_t l = sizeof(s);
    if (getpeername(fd, (struct sockaddr *)&s, &l) != 0) return 0;
    return s.sin_family == AF_INET && s.sin_port == htons(SEP_PORT)
        && s.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
}
static int my_connect(int fd, const struct sockaddr *a, socklen_t len) {
    if (a && a->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)a;
        if (s->sin_port == htons(SEP_PORT) && s->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
    }
    return real_connect(fd, a, len);
}
static ssize_t my_recv(int fd, void *b, size_t n, int f) {
    ssize_t r = real_recv(fd, b, n, f);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && is_sep_socket(fd)) errno = ETIMEDOUT;
    return r;
}
static ssize_t my_recvfrom(int fd, void *b, size_t n, int f, struct sockaddr *fr, socklen_t *fl) {
    ssize_t r = real_recvfrom(fd, b, n, f, fr, fl);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && is_sep_socket(fd)) errno = ETIMEDOUT;
    return r;
}

/* ---------- minimal GOT rebinder ---------- */

struct rebinding { const char *name; void *replacement; };
static struct rebinding g_rb[] = {
    { "connect",  (void *)my_connect  },
    { "recv",     (void *)my_recv     },
    { "recvfrom", (void *)my_recvfrom },
};
static const size_t g_nrb = sizeof(g_rb) / sizeof(g_rb[0]);

static void write_slot(void **slot, void *replacement, int is_auth) {
    void *val = replacement;
#if defined(__arm64e__)
    if (is_auth)
        val = ptrauth_sign_unauthenticated(
                  replacement, ptrauth_key_asia,
                  ptrauth_blend_discriminator((void *)slot, 0));
#else
    (void)is_auth;
#endif
    if (vm_protect(mach_task_self(), (vm_address_t)slot, sizeof(void *), 0,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS)
        *slot = val;
}

static void rebind_section(section_t *sect, intptr_t slide, int is_auth,
                           nlist_t *symtab, char *strtab, uint32_t *indirect) {
    uint32_t *idx = indirect + sect->reserved1;
    void **slots = (void **)((uintptr_t)slide + sect->addr);
    size_t count = sect->size / sizeof(void *);
    for (size_t i = 0; i < count; i++) {
        uint32_t si = idx[i];
        if (si == INDIRECT_SYMBOL_ABS || si == INDIRECT_SYMBOL_LOCAL ||
            si == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
        const char *name = strtab + symtab[si].n_un.n_strx;
        if (name[0] != '_' || name[1] == '\0') continue;
        for (size_t j = 0; j < g_nrb; j++)
            if (strcmp(name + 1, g_rb[j].name) == 0) {
                write_slot(&slots[i], g_rb[j].replacement, is_auth);
                break;
            }
    }
}

static void rebind_image(const struct mach_header *mh, intptr_t slide) {
    const mach_header_t *h = (const mach_header_t *)mh;
    if (h->magic != MH_MAGIC_64) return;
    segment_command_t *linkedit = NULL;
    struct symtab_command *st = NULL;
    struct dysymtab_command *dst = NULL;
    uintptr_t cur = (uintptr_t)h + sizeof(mach_header_t);
    struct load_command *lc = NULL;
    for (uint32_t i = 0; i < h->ncmds; i++, cur += lc->cmdsize) {
        lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            segment_command_t *sg = (segment_command_t *)lc;
            if (strcmp(sg->segname, SEG_LINKEDIT) == 0) linkedit = sg;
        } else if (lc->cmd == LC_SYMTAB)   st  = (struct symtab_command *)lc;
        else if (lc->cmd == LC_DYSYMTAB)   dst = (struct dysymtab_command *)lc;
    }
    if (!linkedit || !st || !dst || !dst->nindirectsyms) return;
    uintptr_t base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    nlist_t  *symtab   = (nlist_t  *)(base + st->symoff);
    char     *strtab   = (char     *)(base + st->stroff);
    uint32_t *indirect = (uint32_t *)(base + dst->indirectsymoff);
    cur = (uintptr_t)h + sizeof(mach_header_t);
    for (uint32_t i = 0; i < h->ncmds; i++, cur += lc->cmdsize) {
        lc = (struct load_command *)cur;
        if (lc->cmd != LC_SEGMENT_64) continue;
        segment_command_t *sg = (segment_command_t *)lc;
        int is_data = strcmp(sg->segname, SEG_DATA) == 0 ||
                      strcmp(sg->segname, "__DATA_CONST") == 0;
        int is_auth = strcmp(sg->segname, "__AUTH")       == 0 ||
                      strcmp(sg->segname, "__AUTH_CONST")  == 0;
        if (!is_data && !is_auth) continue;
        section_t *sec = (section_t *)((uintptr_t)sg + sizeof(segment_command_t));
        for (uint32_t s = 0; s < sg->nsects; s++) {
            uint32_t type = sec[s].flags & SECTION_TYPE;
            if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS)
                rebind_section(&sec[s], slide, is_auth, symtab, strtab, indirect);
        }
    }
}

__attribute__((constructor))
static void sep_timeout_init(void) {
    real_connect  = dlsym(RTLD_NEXT, "connect");
    real_recv     = dlsym(RTLD_NEXT, "recv");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    if (!real_connect)  real_connect  = dlsym(RTLD_DEFAULT, "connect");
    if (!real_recv)     real_recv     = dlsym(RTLD_DEFAULT, "recv");
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_DEFAULT, "recvfrom");
    if (!real_connect || !real_recv) return;
    _dyld_register_func_for_add_image(rebind_image);
}
