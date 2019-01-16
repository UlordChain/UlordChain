#pragma once

#include "BackdoorConnectionInterface.h"
#include "ClientTypes.h"

namespace Pbft {

class DatabaseInterface : public BackdoorConnectionInterface
{
public:
    virtual void TopUp(ClientId id, uint32_t sum) = 0;
    virtual void Withdraw(ClientId id, uint32_t sum) = 0;
    virtual void Transmit(ClientId sourceId, ClientId destinationId, uint32_t sum) = 0;
    virtual uint32_t Balance(ClientId id) = 0;
};

}
