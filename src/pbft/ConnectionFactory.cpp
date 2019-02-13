#include "ConnectionFactory.h"
#include "BackdoorConnection.h"
#include "ClientConnection.h"

namespace Pbft {
// ulord pbft implement
::std::unique_ptr<BackdoorConnectionInterface> ConnectionFactory::CreateBackdoorConnection()
{
    return ::std::make_unique<BackdoorConnection>();
}

::std::unique_ptr<ClientConnectionInterface> ConnectionFactory::CreateClientConnection(ClientId id)
{
    return ::std::make_unique<ClientConnection>(id);
}

void testConnectionFactory()
{
}

void testproduceConnection()
{
}

}
