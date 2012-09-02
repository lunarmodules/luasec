/*=========================================================================*\
* LuaSocket 2.0.2
* Copyright (C) 2004-2007 Diego Nehab
*
* Socket compatibilization module for Unix
*
* The code is now interrupt-safe.
* The penalty of calling select to avoid busy-wait is only paid when
* the I/O call fail in the first place. 
*
* RCS ID: $Id: usocket.c,v 1.38 2007/10/13 23:55:20 diego Exp $
\*=========================================================================*/
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <string.h> 
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include "socket.h"
#include "usocket.h"

/*-------------------------------------------------------------------------*\
* Wait for readable/writable/connected socket with timeout
\*-------------------------------------------------------------------------*/
#ifdef SOCKET_POLL
int socket_waitfd(p_socket ps, int sw, p_timeout tm) {
    int ret;
    struct pollfd pfd;
    pfd.fd = *ps;
    pfd.events = sw;
    pfd.revents = 0;
    if (timeout_iszero(tm)) return IO_TIMEOUT;  /* optimize timeout == 0 case */
    do {
        int t = (int)(timeout_getretry(tm)*1e3);
        ret = poll(&pfd, 1, t >= 0? t: -1);
    } while (ret == -1 && errno == EINTR);
    if (ret == -1) return errno;
    if (ret == 0) return IO_TIMEOUT;
    if (sw == WAITFD_C && (pfd.revents & (POLLIN|POLLERR))) return IO_CLOSED;
    return IO_DONE;
}
#else
int socket_waitfd(p_socket ps, int sw, p_timeout tm) {
    int ret;
    fd_set rfds, wfds, *rp, *wp;
    struct timeval tv, *tp;
    double t;
    if (timeout_iszero(tm)) return IO_TIMEOUT;  /* optimize timeout == 0 case */
    do {
        /* must set bits within loop, because select may have modifed them */
        rp = wp = NULL;
        if (sw & WAITFD_R) { FD_ZERO(&rfds); FD_SET(*ps, &rfds); rp = &rfds; }
        if (sw & WAITFD_W) { FD_ZERO(&wfds); FD_SET(*ps, &wfds); wp = &wfds; }
        t = timeout_getretry(tm);
        tp = NULL;
        if (t >= 0.0) {
            tv.tv_sec = (int)t;
            tv.tv_usec = (int)((t-tv.tv_sec)*1.0e6);
            tp = &tv;
        }
        ret = select(*ps+1, rp, wp, NULL, tp);
    } while (ret == -1 && errno == EINTR);
    if (ret == -1) return errno;
    if (ret == 0) return IO_TIMEOUT;
    if (sw == WAITFD_C && FD_ISSET(*ps, &rfds)) return IO_CLOSED;
    return IO_DONE;
}
#endif


/*-------------------------------------------------------------------------*\
* Initializes module 
\*-------------------------------------------------------------------------*/
int socket_open(void) {
    /* instals a handler to ignore sigpipe or it will crash us */
    signal(SIGPIPE, SIG_IGN);
    return 1;
}

/*-------------------------------------------------------------------------*\
* Close module 
\*-------------------------------------------------------------------------*/
int socket_close(void) {
    return 1;
}

/*-------------------------------------------------------------------------*\
* Close and inutilize socket
\*-------------------------------------------------------------------------*/
void socket_destroy(p_socket ps) {
    if (*ps != SOCKET_INVALID) {
        socket_setblocking(ps);
        close(*ps);
        *ps = SOCKET_INVALID;
    }
}

/*-------------------------------------------------------------------------*\
* Put socket into blocking mode
\*-------------------------------------------------------------------------*/
void socket_setblocking(p_socket ps) {
    int flags = fcntl(*ps, F_GETFL, 0);
    flags &= (~(O_NONBLOCK));
    fcntl(*ps, F_SETFL, flags);
}

/*-------------------------------------------------------------------------*\
* Put socket into non-blocking mode
\*-------------------------------------------------------------------------*/
void socket_setnonblocking(p_socket ps) {
    int flags = fcntl(*ps, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(*ps, F_SETFL, flags);
}

/*-------------------------------------------------------------------------*\
* Error translation functions
* Make sure important error messages are standard
\*-------------------------------------------------------------------------*/
const char *socket_strerror(int err) {
    if (err <= 0) return io_strerror(err);
    switch (err) {
        case EADDRINUSE: return "address already in use";
        case EISCONN: return "already connected";
        case EACCES: return "permission denied";
        case ECONNREFUSED: return "connection refused";
        case ECONNABORTED: return "closed";
        case ECONNRESET: return "closed";
	case EPIPE: return "closed";
        case ETIMEDOUT: return "timeout";
        default: return strerror(errno);
    }
}

/*-------------------------------------------------------------------------*\
* Underline error code.
\*-------------------------------------------------------------------------*/
int socket_error()
{
  return errno;
}

