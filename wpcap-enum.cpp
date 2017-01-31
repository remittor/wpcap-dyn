#include <winsock2.h>
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>

#include "pcap.h"

struct wpcap_dyn * wpc = NULL;

int wmain(int argc, wchar_t ** argv)
{
    LPWSTR modname = NULL;
    char ntop_buf[INET6_ADDRSTRLEN];

    if (argc > 1)
        modname = argv[1];
    int hr = wpcap_load(modname, &wpc);
    if (hr) {
        printf("ERROR: can't load wpcap.dll (err = %d) \n", hr);
        return hr;
    }
    printf("ver: %s \n", wpc->wpc.version);
    hr = wpcap_enum_iface(wpc);
    if (hr < 0) {
        printf("ERROR: can't init wpcap.dll (err = %d) \n", hr);
        return hr;
    }
    printf("dcnt = %d \n", hr);

    pcap_if_t * alldevs = wpc->wpc.devlist;
    for (pcap_if_t * dev=alldevs; dev; dev = dev->next) {
        printf("%s\n", dev->name);
        if (dev->description)
            printf("\tDesc: %s\n",dev->description); 
        for (pcap_addr_t * a=dev->addresses; a ; a = a->next) {
            if (!a->addr)
                continue;
            switch(a->addr->sa_family) {
            case AF_INET:
                printf("\t%s\t\t", inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
                if (a->netmask)
                    printf(" [%s]\t", inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
                if (a->broadaddr)
                    printf(" (%s)\t", inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
                if (a->dstaddr)
                    printf(" {%s}\t", inet_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr)); 
                printf("\n");
                break;
            case AF_INET6:
                printf("\t%s\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                if (a->netmask)
                    printf(" [%s]\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                if (a->broadaddr)
                    printf(" (%s)\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                if (a->dstaddr)
                    printf(" {%s}\t", inet_ntop(AF_INET6, ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr, ntop_buf, sizeof ntop_buf));
                printf("\n");
                break;
            default:
                printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
                break;
            }
        }
    }

    if (wpc)
        wpcap_free(wpc);
    return 0;
}

