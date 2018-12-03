#pragma once

#include <memory>
#include "BackdoorConnectionInterface.h"
#include "ClientConnectionInterface.h"

namespace Pbft {

class ConnectionFactory
{
public:
    ConnectionFactory() = delete;
    ConnectionFactory(const ConnectionFactory&) = delete;

    ConnectionFactory& operator=(const ConnectionFactory&) = delete;

    static ::std::unique_ptr<BackdoorConnectionInterface> CreateBackdoorConnection();
    static ::std::unique_ptr<ClientConnectionInterface> CreateClientConnection(ClientId id);
};

}
