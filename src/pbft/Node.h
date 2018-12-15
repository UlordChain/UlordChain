#pragma once

#include "NodeInterface.h"
#include "LinkInterface.h"
#include <boost/optional.hpp>
#include <mutex>

namespace Pbft {

class Node : public NodeInterface
{
public:
    Node(::std::shared_ptr<LinkInterface> linkToSet, NodeId id, const ::std::list<Command>& commandsToSet);

private:
    virtual const ::std::list<Command>& Commands() const override;
    virtual void SetNodeCount(uint32_t count) override;
    virtual void SetFaulty() override;
    virtual void SetOperational() override;

    void OnReceive(const Message& receivedMessage);
    void OnPrePrepare(const Message& receivedMessage);
    void OnPrepare(const Message& receivedMessage);
    void OnCommit(const Message& receivedMessage);

    void RegisterReceivedMessage(TransactionId transactionId, const Message& receivedMessage);
    bool TransactionCorrect(TransactionId id) const;
    bool MessageCorrect(const Message& receivedMessage) const;

    Message PrepareMessageToSend(TransactionId transactionId) const;
    void InitiateTransaction(const Message& messageToSend);

    void PrePrepareCommand();
    void PrePrepareTopUpCommand();
    void PrePrepareWithdrawCommand();
    void PrePrepareTransmitCommand();
    void PrePrepareBalanceCommand();
    void PrePrepareSubtractingCommand(ClientId clientId, uint32_t sum);

    void CommitSucceededCommand();

    ::boost::optional<uint32_t> GetBalance(ClientId id) const;
    ::boost::optional<int32_t> CommandEffect(const Command& command, ClientId clientId) const;

    uint32_t NodeCount() const;
    bool Faulty() const;

    mutable ::std::mutex mutex;
    ::std::shared_ptr<LinkInterface> link;
    // ::boost::multi_index_container must be used instead of the ::std::list.
    // ::std::list is taken for the implementation simplification
    ::std::list<Command> commands;
    ::boost::signals2::scoped_connection connection;
    uint32_t nodeCount{0u};
    bool faulty{false};
    Message message;
    uint32_t messageCount{0u};
    uint32_t validMessageCount{0u};
};

}
