#pragma once

// TCPOPT_CC, TCPOPT_CCNEW and TCPOPT_CCECHO are defined in the MacOS's tcp.h.
#ifdef TCPOPT_CC
#undef TCPOPT_CC
#endif // TCPOPT_CC
#ifdef TCPOPT_CCNEW
#undef TCPOPT_CCNEW
#endif // TCPOPT_CCNEW
#ifdef TCPOPT_CCECHO
#undef TCPOPT_CCECHO
#endif // TCPOPT_CCECHO
#include <TcpLayer.h>