#ifndef WSOCKET_H
#define WSOCKET_H
/*=========================================================================*\
* LuaSocket 2.0.2
* Copyright (C) 2004-2007 Diego Nehab
*
* Socket compatibilization module for Win32
*
* RCS ID: $Id: wsocket.h 2 2006-04-30 19:30:47Z brunoos $
\*=========================================================================*/

/*=========================================================================*\
* WinSock include files
\*=========================================================================*/
#include <winsock.h>

#define WAITFD_R        1
#define WAITFD_W        2
#define WAITFD_E        4
#define WAITFD_C        (WAITFD_E|WAITFD_W)

#define SOCKET_INVALID (INVALID_SOCKET)

typedef int socklen_t;
typedef SOCKET t_socket;
typedef t_socket *p_socket;

#endif /* WSOCKET_H */
