#ifndef SOCKET_H
#define SOCKET_H
/*=========================================================================*\
* LuaSocket 2.0.2
* Copyright (C) 2004-2007 Diego Nehab
*
* Socket compatibilization module
*
* BSD Sockets and WinSock are similar, but there are a few irritating
* differences. Also, not all *nix platforms behave the same. This module
* (and the associated usocket.h and wsocket.h) factor these differences and
* creates a interface compatible with the io.h module.
*
* RCS ID: $Id: socket.h 2 2006-04-30 19:30:47Z brunoos $
\*=========================================================================*/
#include "io.h"

/*=========================================================================*\
* Platform specific compatibilization
\*=========================================================================*/
#ifdef _WIN32
#include "wsocket.h"
#else
#include "usocket.h"
#endif

/*=========================================================================*\
* The connect and accept functions accept a timeout and their
* implementations are somewhat complicated. We chose to move
* the timeout control into this module for these functions in
* order to simplify the modules that use them. 
\*=========================================================================*/
#include "timeout.h"

/*=========================================================================*\
* Functions bellow implement a comfortable platform independent 
* interface to sockets
\*=========================================================================*/
int socket_open(void);
int socket_close(void);
void socket_destroy(p_socket ps);
void socket_setnonblocking(p_socket ps);
void socket_setblocking(p_socket ps);
int socket_waitfd(p_socket ps, int sw, p_timeout tm);
const char *socket_strerror(int err);
int socket_error();

#endif /* SOCKET_H */
