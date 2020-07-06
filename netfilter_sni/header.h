#ifndef HEADER_H
#define HEADER_H
#pragma once
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <algorithm>
#include <map>

#define TCP 0x06
#endif // HEADER_H
