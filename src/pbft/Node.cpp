#include "Node.h"
#include "Utilities.h"

namespace Pbft {

Node::Node(::std::shared_ptr<LinkInterface> linkToSet, NodeId id, const ::std::list<Command>& commandsToSet)
    : link(linkToSet)
    , commands(commandsToSet)
{
    connection = link->Receive.connect([this](const Message& receivedMessage){OnReceive(receivedMessage);});
    message.nodeId = id;
}

const ::std::list<Command>& Node::Commands() const
{
    ::std::lock_guard<::std::mutex> lock(mutex);
    return commands;
}

void Node::SetNodeCount(uint32_t count)
{
    ::std::lock_guard<::std::mutex> lock(mutex);
    nodeCount = count;
}

void Node::SetFaulty()
{
    ::std::lock_guard<::std::mutex> lock(mutex);
    faulty = true;
}

void Node::SetOperational()
{
    ::std::lock_guard<::std::mutex> lock(mutex);
    faulty = false;
}

void Node::OnReceive(const Message& receivedMessage)
{
    switch (receivedMessage.transactionId)
    {
        case TransactionId::PrePrepare:
        {
            OnPrePrepare(receivedMessage);
            break;
        }
        case TransactionId::Prepare:
        {
            OnPrepare(receivedMessage);
            break;
        }
        case TransactionId::Commit:
        {
            OnCommit(receivedMessage);
            break;
        }
    }
}

void Node::OnPrePrepare(const Message& receivedMessage)
{
    if ((static_cast<int32_t>(receivedMessage.id) - static_cast<int32_t>(message.id)) <= 0)
    {
        return;
    }

    message.transactionId = receivedMessage.transactionId;
    message.id = receivedMessage.id;
    message.command = receivedMessage.command;
    PrePrepareCommand();
    InitiateTransaction(PrepareMessageToSend(TransactionId::Prepare));
}

void Node::OnPrepare(const Message& receivedMessage)
{
    RegisterReceivedMessage(TransactionId::PrePrepare, receivedMessage);
    if (messageCount == NodeCount())
    {
        message.transactionId = TransactionId::Prepare;
        if (Utilities::TransactionConfirmed(messageCount, validMessageCount))
        {
            InitiateTransaction(PrepareMessageToSend(TransactionId::Commit));
        }
        else
        {
            message.resultId = ResultId::Failure;
            InitiateTransaction(PrepareMessageToSend(TransactionId::Result));
        }
    }
}

void Node::OnCommit(const Message& receivedMessage)
{
    RegisterReceivedMessage(TransactionId::Prepare, receivedMessage);
    if (messageCount == NodeCount())
    {
        message.transactionId = TransactionId::Commit;
        if (Utilities::TransactionConfirmed(messageCount, validMessageCount))
        {
            CommitSucceededCommand();
        }
        else
        {
            message.resultId = ResultId::Failure;
        }

        InitiateTransaction(PrepareMessageToSend(TransactionId::Result));
    }
}

void Node::RegisterReceivedMessage(TransactionId transactionId, const Message& receivedMessage)
{
    ++messageCount;
    if (TransactionCorrect(transactionId) && MessageCorrect(receivedMessage))
    {
        ++validMessageCount;
    }
}

bool Node::TransactionCorrect(TransactionId id) const
{
    return (message.transactionId == id);
}

bool Node::MessageCorrect(const Message& receivedMessage) const
{
    return ((receivedMessage.id == message.id) && (receivedMessage.command == message.command));
}

Message Node::PrepareMessageToSend(TransactionId transactionId) const
{
    auto messageToSend(message);
    messageToSend.transactionId = transactionId;
    if ((messageToSend.transactionId == TransactionId::Prepare) && Faulty())
    {
        if (messageToSend.command.id == CommandId::Balance)
        {
            messageToSend.command.balance.sum = Utilities::Random<decltype(messageToSend.command.balance.
                sum)>();
        }
        else
        {
            --messageToSend.id;
        }
    }

    return messageToSend;
}

void Node::InitiateTransaction(const Message& messageToSend)
{
    messageCount = 0;
    validMessageCount = 0;
    link->Send(messageToSend);
}

void Node::PrePrepareCommand()
{
    switch (message.command.id)
    {
        case CommandId::TopUp:
        {
            PrePrepareTopUpCommand();
            break;
        }
        case CommandId::Withdraw:
        {
            PrePrepareWithdrawCommand();
            break;
        }
        case CommandId::Transmit:
        {
            PrePrepareTransmitCommand();
            break;
        }
        case CommandId::Balance:
        {
            PrePrepareBalanceCommand();
            break;
        }
    }
}

void Node::PrePrepareTopUpCommand()
{
    message.resultId = ResultId::Success;
}

void Node::PrePrepareWithdrawCommand()
{
    PrePrepareSubtractingCommand(message.command.withdraw.id, message.command.withdraw.sum);
}

void Node::PrePrepareTransmitCommand()
{
    PrePrepareSubtractingCommand(message.command.transmit.sourceId, message.command.transmit.sum);
}

void Node::PrePrepareBalanceCommand()
{
    if (auto balance = GetBalance(message.command.balance.id))
    {
        message.command.balance.sum = *balance;
        message.resultId = ResultId::Success;
    }
    else
    {
        message.command.balance.sum = 0;
        message.resultId = ResultId::Failure;
    }
}

void Node::PrePrepareSubtractingCommand(ClientId clientId, uint32_t sum)
{
    if (auto balance = GetBalance(clientId))
    {
        if (*balance >= sum)
        {
            message.resultId = ResultId::Success;
            return;
        }
    }

    message.resultId = ResultId::Failure;
}

void Node::CommitSucceededCommand()
{
    if ((message.command.id != CommandId::Balance) && (message.resultId == ResultId::Success))
    {
        commands.emplace_back(message.command);
    }
}

::boost::optional<uint32_t> Node::GetBalance(ClientId id) const
{
    auto clientFound(false);
    auto balance(0u);
    for (const auto& command : commands)
    {
        if (auto effect = CommandEffect(command, id))
        {
            clientFound = true;
            balance += static_cast<uint32_t>(*effect);
        }
    }

    if (!clientFound)
    {
        return {};
    }

    return balance;
}

::boost::optional<int32_t> Node::CommandEffect(const Command& command, ClientId clientId) const
{
    switch (command.id)
    {
        case CommandId::TopUp:
        {
            if (command.topUp.id == clientId)
            {
                return static_cast<int32_t>(command.topUp.sum);
            }
            
            break;
        }
        case CommandId::Withdraw:
        {
            if (command.withdraw.id == clientId)
            {
                return -static_cast<int32_t>(command.withdraw.sum);
            }

            break;
        }
        case CommandId::Transmit:
        {
            if (command.transmit.sourceId == clientId)
            {
                return -static_cast<int32_t>(command.transmit.sum);
            }
            else if (command.transmit.destinationId == clientId)
            {
                return static_cast<int32_t>(command.transmit.sum);
            }

            break;
        }
    }

    return {};
}

uint32_t Node::NodeCount() const
{
    ::std::lock_guard<::std::mutex> lock(mutex);
    return nodeCount;
}

bool Node::Faulty() const
{
    ::std::lock_guard<::std::mutex> lock(mutex);
    return faulty;
}

}
