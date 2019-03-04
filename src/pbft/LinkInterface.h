#pragma once

#include "DatabaseTypes.h"
#include <boost/signals2.hpp>

namespace Pbft {

class LinkInterface
{
public:
    LinkInterface(const LinkInterface&) = delete;
    virtual ~LinkInterface() = default;

    LinkInterface& operator=(const LinkInterface&) = delete;

    virtual void Send(const Message& message) const = 0;

    ::boost::signals2::signal<void(const Message&)> Receive;

    ::boost::signals2::signal<void(const Message&)> Send;

protected:
    LinkInterface() = default;
};

}
