#pragma once

#include "DatabaseInterface.h"

namespace Pbft {
// dpos connect node
class Connection
{
public:
    explicit Connection(DatabaseInterface& databaseToSet);

    virtual DatabaseInterface& Database() const;
    bool    isConnected;
private:
    DatabaseInterface& database;
};

}
