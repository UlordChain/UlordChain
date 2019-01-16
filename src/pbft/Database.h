#pragma once

#include "DatabaseInterface.h"
#include "DatabaseFactoryInterface.h"
#include <future>

namespace Pbft {
//pbft set node 
class Database : public DatabaseInterface
{
public:
    explicit Database(::std::shared_ptr<DatabaseFactoryInterface> factoryToSet);

    static DatabaseInterface& Instance();

private:
    virtual NodeId CreateNode() override;
    virtual void DeleteNode(NodeId id) override;
    virtual void SetFaulty(NodeId id) override;
    virtual void SetOperational(NodeId id) override;

    virtual void TopUp(ClientId id, uint32_t sum) override;
    virtual void Withdraw(ClientId id, uint32_t sum) override;
    virtual void Transmit(ClientId sourceId, ClientId destinationId, uint32_t sum) override;
    virtual uint32_t Balance(ClientId id) override;

    void CheckDatabase() const;
    NodeId FreeNodeId() const;
    void SetNodeCount() const;
    // pbft connesus  transaction 
    void ExecuteTransaction();
    void WaitResult();

    void OnReceive(const Message& receivedMessage);

    void ProcessSucceededCommands();
    void CheckSucceededCommandsReceived();
    const Command& GetCommandWithMaximumReplication(uint32_t& count) const;
    void CheckCommandWithMaximumReplication(const Command& command, uint32_t count);
    void RegisterResult(const Command& command);

    static ::std::mutex mutex;
    static ::std::unique_ptr<DatabaseInterface> instance;
    ::std::shared_ptr<DatabaseFactoryInterface> factory;
    ::std::shared_ptr<LinkInterface> link;
    ::boost::signals2::scoped_connection connection;
    ::std::map<NodeId, ::std::shared_ptr<NodeInterface>> nodes;
    Message message;
    uint32_t messageCount{0u};
    ::std::map<Command, uint32_t> succeededCommands;
    ::std::unique_ptr<::std::promise<void>> promise;
};

}
