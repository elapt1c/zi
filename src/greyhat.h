#ifndef GREYHAT_H
#define GREYHAT_H

#include "zorpinvader.h"
#include <stdint.h>

void greyhat_init(void);
void greyhat_scan(ipaddress ip, const unsigned char *px, unsigned length);
void log_banner(const char *ip, unsigned port, unsigned proto, const char *banner);

#endif
