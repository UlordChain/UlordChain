#include "BackdoorConnection.h"
#include "Database.h"

namespace Pbft {

BackdoorConnection::BackdoorConnection() : connection(Database::Instance())
{
}

NodeId BackdoorConnection::CreateNode()
{
    return connection.Database().CreateNode();
}

void BackdoorConnection::DeleteNode(NodeId id)
{
    connection.Database().DeleteNode(id);
}

void BackdoorConnection::SetFaulty(NodeId id)
{
    connection.Database().SetFaulty(id);
}

void BackdoorConnection::SetOperational(NodeId id)
{
    connection.Database().SetOperational(id);
}

}
