#ifndef USOCKET_H
#define USOCKET_H
/*=========================================================================*\
* LuaSocket 2.0.2
* Copyright (C) 2004-2007 Diego Nehab
*
* Socket compatibilization module for Unix
*
* RCS ID: $Id: usocket.h 6 2006-04-30 20:33:05Z brunoos $
\*=========================================================================*/

#ifdef SOCKET_POLL
#include <sys/poll.h>
#define WAITFD_R        POLLIN
#define WAITFD_W        POLLOUT
#define WAITFD_C        (POLLIN|POLLOUT)
#else
#define WAITFD_R        1
#define WAITFD_W        2
#define WAITFD_C        (WAITFD_R|WAITFD_W)
#endif

typedef int t_socket;
typedef t_socket *p_socket;

#define SOCKET_INVALID (-1)

#endif /* USOCKET_H */
