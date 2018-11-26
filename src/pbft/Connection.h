#pragma once

#include "DatabaseInterface.h"

namespace Pbft {

class Connection
{
public:
    explicit Connection(DatabaseInterface& databaseToSet);

    virtual DatabaseInterface& Database() const;

private:
    DatabaseInterface& database;
};

}
