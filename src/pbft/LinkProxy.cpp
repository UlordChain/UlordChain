#include "LinkProxy.h"

namespace Pbft {

LinkProxy::LinkProxy()
{
    try
    {
        context = ::std::make_unique<::boost::asio::io_service>();
        work = ::std::make_unique<::boost::asio::io_service::work>(*context);
        strand = ::std::make_unique<::boost::asio::io_service::strand>(*context);
        thread = ::std::make_unique<::std::thread>([this]{context->run();});
    }
    catch (const std::exception&)
    {
        Uninitialize();
        throw;
    }
}

LinkProxy::~LinkProxy()
{
    Uninitialize();
}

void LinkProxy::Uninitialize()
{
    if (thread)
    {
        context->stop();
        thread->join();
    }

    thread.reset();
    strand.reset();
    work.reset();
    context.reset();
}

void LinkProxy::Send(const Message& message) const
{
    strand->post([message, this]{Receive(message);});
}

}
