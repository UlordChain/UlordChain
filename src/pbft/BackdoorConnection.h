#pragma once

#include "BackdoorConnectionInterface.h"
#include "Connection.h"

namespace Pbft {

class BackdoorConnection : public BackdoorConnectionInterface
{
public:
    BackdoorConnection();

private:
    virtual NodeId CreateNode() override;
    virtual void DeleteNode(NodeId id) override;
    virtual void SetFaulty(NodeId id) override;
    virtual void SetOperational(NodeId id) override;

    Connection connection;
};

}
