#pragma once

#include "ClientConnectionInterface.h"
#include "Connection.h"

namespace Pbft {

class ClientConnection : public ClientConnectionInterface
{
public:
    explicit ClientConnection(ClientId idToSet);

private:
    virtual void TopUp(uint32_t sum) override;
    virtual void Withdraw(uint32_t sum) override;
    virtual void Transmit(ClientId destinationId, uint32_t sum) override;
    virtual uint32_t Balance() const override;

    Connection connection;
    ClientId id;
};

}
