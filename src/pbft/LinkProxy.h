#pragma once

#include "LinkInterface.h"
#include <boost/asio.hpp>
#include <thread>

namespace Pbft {

class LinkProxy : public LinkInterface
{
public:
    LinkProxy();
    virtual ~LinkProxy() override;

private:
    void Uninitialize();

    virtual void Send(const Message& message) const override;

    ::std::unique_ptr<::boost::asio::io_service> context;
    ::std::unique_ptr<::boost::asio::io_service::work> work;
    ::std::unique_ptr<::boost::asio::io_service::strand> strand;
    ::std::unique_ptr<::std::thread> thread;
};

}
