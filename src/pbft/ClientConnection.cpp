#include "ClientConnection.h"
#include "Database.h"

namespace Pbft {
// dpos algorithm
ClientConnection::ClientConnection(ClientId idToSet)
    : connection(Database::Instance())
    , id(idToSet)
{
}
//sort dpos list
void sortlist()
{
}
void ClientConnection::TopUp(uint32_t sum)
{
    return connection.Database().TopUp(id, sum);
}

void ClientConnection::Withdraw(uint32_t sum)
{
    return connection.Database().Withdraw(id, sum);
}

void ClientConnection::Stat(uint32_t sum)
{
   return ;
}

void ClientConnection::Transmit(ClientId destinationId, uint32_t sum)
{
    return connection.Database().Transmit(id, destinationId, sum);
}

uint32_t ClientConnection::Balance() const
{
    return connection.Database().Balance(id);
}

}
