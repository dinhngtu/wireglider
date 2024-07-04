#pragma once

#include <algorithm>
#include <cstring>
#include <system_error>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fmt/format.h>
#include <tdutil/fildes.hpp>

namespace wireglider {

class UnixServer {
public:
    UnixServer(const std::string &path) : _path(path) {
        if (_path.size() > std::size(_sun.sun_path) - 1)
            throw std::invalid_argument("socket path too long");
        else if (_path.find('\0') != _path.npos)
            throw std::invalid_argument("socket path contains null");

        _sock = tdutil::FileDescriptor(socket(AF_UNIX, SOCK_STREAM, 0));

        struct stat st;
        if (stat(_path.c_str(), &st) == 0 && (st.st_mode & S_IFMT) != S_IFSOCK)
            throw std::runtime_error(fmt::format("refusing to unlink non-socket file {}", _path));
        else
            unlink(_path.c_str());

        _sun.sun_family = AF_UNIX;
        strncpy(&_sun.sun_path[0], _path.c_str(), std::size(_sun.sun_path));
        _sun.sun_path[std::size(_sun.sun_path) - 1] = 0;

        if (bind(_sock, reinterpret_cast<sockaddr *>(&_sun), sizeof(_sun)) < 0)
            throw std::system_error(errno, std::system_category(), "bind(AF_UNIX)");
    }

    constexpr tdutil::FileDescriptor &fd() {
        return _sock;
    }

private:
    std::string _path;
    sockaddr_un _sun;
    tdutil::FileDescriptor _sock;
};

} // namespace wireglider
