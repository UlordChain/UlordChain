#pragma once

#include <cstdint>
#include <random>

namespace Pbft {
// util tool data tran manager  
class Utilities
{
public:
    Utilities() = delete;
    Utilities(const Utilities&) = delete;

    Utilities& operator=(const Utilities&) = delete;

    static bool TransactionConfirmed(uint32_t nodeCount, uint32_t messageCount)
    {
        return (messageCount >= (((nodeCount - 1) / 3) + 1));
    }

    template<typename Type> static Type Random()
    {
        ::std::random_device device;
        ::std::mt19937 engine(device());
        ::std::uniform_int_distribution<Type> distribution(::std::numeric_limits<Type>::min(),
            ::std::numeric_limits<Type>::max());
        return distribution(engine);
    }
};

}
