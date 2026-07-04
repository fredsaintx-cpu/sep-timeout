// vcam_sep_timeout.c — load-time hook: 5s SO_RCVTIMEO on SEP socket (127.0.0.1:1789)
// Compiles with: clang -arch arm64 -arch arm64e -dynamiclib -isysroot <SDK> -miphoneos-version-min=14.0
#include "fishhook.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>

static const in_port_t SEP_PORT = 1789;

static int      (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t  (*orig_recv)(int, void *, size_t, int);

// Check if this fd's peer is 127.0.0.1:1789
static int is_sep_socket(int fd) {
    struct sockaddr_in sin; socklen_t l = sizeof(sin);
    if (getpeername(fd, (struct sockaddr *)&sin, &l) != 0) return 0;
    return sin.sin_family == AF_INET &&
           sin.sin_port   == htons(SEP_PORT) &&
           sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
}

static int hooked_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr && addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (sin->sin_port == htons(SEP_PORT) &&
            sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
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

__attribute__((constructor))
static void vcam_sep_timeout_init(void) {
    rebind_symbols((struct rebind[]){
        { "connect", (void *)hooked_connect, (void **)&orig_connect },
        { "recv",    (void *)hooked_recv,    (void **)&orig_recv    },
    }, 2);
}
