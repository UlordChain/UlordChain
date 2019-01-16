#pragma once

#include "LinkInterface.h"
#include "NodeInterface.h"

namespace Pbft {
//ulord database connect manager 
class DatabaseFactoryInterface
{
public:
    DatabaseFactoryInterface(const DatabaseFactoryInterface&) = delete;
    virtual ~DatabaseFactoryInterface() = default;

    DatabaseFactoryInterface& operator=(const DatabaseFactoryInterface&) = delete;

    virtual ::std::unique_ptr<LinkInterface> CreateLink() const = 0;
    virtual ::std::unique_ptr<NodeInterface> CreateNode(::std::shared_ptr<LinkInterface> linkToSet,
        NodeId idToSet) const = 0;
    virtual ::std::unique_ptr<NodeInterface> CreateNode(::std::shared_ptr<LinkInterface> linkToSet,
        NodeId idToSet, const ::std::list<Command>& commands) const = 0;

protected:
    DatabaseFactoryInterface() = default;
};

}
