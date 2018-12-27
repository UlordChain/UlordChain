#include "Connection.h"

namespace Pbft {

// pbft algorithm
Connection::Connection(DatabaseInterface& databaseToSet) : database(databaseToSet)
{
}

DatabaseInterface& Connection::Database() const
{
    return database;
}
Connection::test()
{

}
}
