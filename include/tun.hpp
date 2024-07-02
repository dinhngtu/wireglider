#pragma once

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include "virtio_net.hpp"
#include <tdutil/fildes.hpp>
#include "netutil.hpp"

namespace wireglider {

class Tun {
public:
    explicit Tun(const char *devname) {
        _tun = tdutil::FileDescriptor("/dev/net/tun", O_RDWR);
        _tun.check();

        unsigned int avail_feat;
        if (ioctl(_tun, TUNGETFEATURES, &avail_feat) < 0)
            avail_feat = IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE;

        _feat = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
        if ((_feat & avail_feat) != _feat)
            throw std::runtime_error("unsupported tunnel features");
        if (avail_feat & IFF_MULTI_QUEUE)
            _feat |= IFF_MULTI_QUEUE;

        Ifr ifr(devname);
        ifr->ifr_flags = _feat;
        if (ioctl(_tun, TUNSETIFF, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(TUNSETIFF)");

        int vnethdrsz = sizeof(virtio_net_hdr);
        if (ioctl(_tun, TUNSETVNETHDRSZ, &vnethdrsz) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(TUNSETVNETHDRSZ)");

        unsigned long offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN | TUN_F_USO4 | TUN_F_USO6;
        if (ioctl(_tun, TUNSETOFFLOAD, offload) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(TUNSETOFFLOAD)");

        _name = get_name();
    }

    constexpr tdutil::FileDescriptor &fd() {
        return _tun;
    }

    constexpr const std::string &name() const {
        return _name;
    }

    constexpr short features() const {
        return _feat;
    }

    void set_address(sockaddr_in sin, uint32_t prefixlen) {
        auto tunsock = tdutil::FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));
        tunsock.check();

        Ifr ifr(_name);
        memcpy(&ifr->ifr_addr, &sin, sizeof(sin));
        if (ioctl(tunsock, SIOCSIFADDR, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(SIOCSIFADDR)");

        ifr = Ifr(_name);
        sockaddr_in mask;
        mask.sin_family = AF_INET;
        // https://stackoverflow.com/a/22336357/8642889
        mask.sin_addr.s_addr = prefixlen ? htonl(~((1 << (32 - prefixlen)) - 1)) : 0;
        memcpy(&ifr->ifr_addr, &mask, sizeof(mask));
        if (ioctl(tunsock, SIOCSIFNETMASK, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(SIOCSIFNETMASK)");
    }

    void set_address(in_addr addr, uint32_t prefixlen) {
        sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr = addr;
        set_address(sin, prefixlen);
    }

    void set_address6(sockaddr_in6 sin6, uint32_t prefixlen) {
        auto tunsock = tdutil::FileDescriptor(socket(AF_INET6, SOCK_DGRAM, 0));
        tunsock.check();

        in6_ifreq ifr6;
        memset(&ifr6, 0, sizeof(ifr6));
        memcpy(&ifr6.ifr6_addr, &sin6.sin6_addr, sizeof(ifr6.ifr6_addr));
        ifr6.ifr6_prefixlen = prefixlen;
        ifr6.ifr6_ifindex = get_ifindex(tunsock);
        if (ioctl(tunsock, SIOCSIFADDR, &ifr6) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(SIOCSIFADDR)");
    }

    void set_address6(in6_addr addr, uint32_t prefixlen) {
        sockaddr_in6 sin6;
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = addr;
        set_address6(sin6, prefixlen);
    }

    void set_up(bool up) {
        auto tunsock = tdutil::FileDescriptor(socket(AF_INET6, SOCK_DGRAM, 0));
        tunsock.check();

        Ifr ifr(_name);
        if (ioctl(tunsock, SIOCGIFFLAGS, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(SIOCGIFFLAGS)");
        if (up)
            ifr->ifr_flags |= IFF_UP;
        else
            ifr->ifr_flags &= ~IFF_UP;
        if (ioctl(tunsock, SIOCSIFFLAGS, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(SIOCSIFFLAGS)");
    }

    Tun clone() {
        if (!(_feat & IFF_MULTI_QUEUE))
            throw std::logic_error("tunnel without IFF_MULTI_QUEUE cannot be cloned");
        return Tun(_name.c_str());
    }

private:
    std::string get_name() {
        Ifr ifr;
        if (ioctl(_tun, TUNGETIFF, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(TUNGETIFF)");
        return std::string(ifr->ifr_name);
    }

    int get_ifindex(tdutil::FileDescriptor &sock) {
        Ifr ifr(_name);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
            throw std::system_error(errno, std::system_category(), "ioctl(SIOCGIFINDEX)");
        return ifr->ifr_ifindex;
    }

private:
    unsigned int _feat;
    tdutil::FileDescriptor _tun;
    std::string _name;
};

} // namespace wireglider
