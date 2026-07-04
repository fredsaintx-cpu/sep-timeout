// vcam_sep_timeout.c — 5s recv timeout on SEP socket (127.0.0.1:1789)
// Uses dyld interpose — no fishhook needed
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>

static const in_port_t SEP_PORT = 1789;

// Original function pointers
static int      (*real_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t  (*real_recv)(int, void *, size_t, int);
static ssize_t  (*real_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);

// Check if this fd is connected to 127.0.0.1:1789
static int is_sep_socket(int fd) {
    struct sockaddr_in sin; socklen_t len = sizeof(sin);
    if (getpeername(fd, (struct sockaddr *)&sin, &len) != 0) return 0;
    return sin.sin_family == AF_INET &&
           sin.sin_port   == htons(SEP_PORT) &&
           sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK);
}

static int my_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (addr && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (sin->sin_family == AF_INET &&
            sin->sin_port == htons(SEP_PORT) &&
            sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            struct timeval tv;
            tv.tv_sec = 5; tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
    }
    return real_connect(fd, addr, len);
}

static ssize_t my_recv(int fd, void *buf, size_t n, int flags) {
    ssize_t r = real_recv(fd, buf, n, flags);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && is_sep_socket(fd))
        errno = ETIMEDOUT;
    return r;
}

static ssize_t my_recvfrom(int fd, void *buf, size_t n, int flags,
                            struct sockaddr *from, socklen_t *fromlen) {
    ssize_t r = real_recvfrom(fd, buf, n, flags, from, fromlen);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && is_sep_socket(fd))
        errno = ETIMEDOUT;
    return r;
}

// DYLD interpose table — dyld swaps these at load time
__attribute__((used))
__attribute__((section("__DATA,__interpose")))
static const struct {
    const void *replacement;
    const void *target;
} interpose_table[] = {
    { my_connect,  &connect  },
    { my_recv,     &recv     },
    { my_recvfrom, &recvfrom },
};

__attribute__((constructor))
static void init(void) {
    // Store originals via dlsym (belt and suspenders)
    real_connect  = dlsym(RTLD_NEXT, "connect");
    real_recv     = dlsym(RTLD_NEXT, "recv");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
}
