#ifndef RANDOM_ANONYMIZER_H
#define RANDOM_ANONYMIZER_H

#include "anonymizer.h"

#include <chrono>
#include <random>

class RandomAnonymizer : public Anonymizer
{
public:
    RandomAnonymizer();
    virtual std::pair<std::string,std::string> map(
            const pcpp::IPv4Address& ip1,
            const pcpp::IPv4Address& ip2);
private:
    unsigned mSeed;
    std::default_random_engine mGenerator;
    std::uniform_int_distribution<int> mDistribution;
};

#endif
