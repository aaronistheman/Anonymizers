#ifndef RANDOM_ANONYMIZER_H
#define RANDOM_ANONYMIZER_H

#include "anonymizer.h"

#include <chrono>
#include <random>
#include <unordered_map>

typedef std::unordered_map<uint32_t,std::string> IpMap;

// Does not drop payload.
class RandomAnonymizer : public Anonymizer
{
public:
    // If preserve flows, then a given IP address will always
    // be mapped to the same initially random IP address (whether
    // used as a source or a destination).
    RandomAnonymizer(bool preserveFlows=false);
    ~RandomAnonymizer();
    virtual std::pair<std::string,std::string> Map(
            const pcpp::IPv4Address& ip1,
            const pcpp::IPv4Address& ip2);
private:
    void GenerateRandomIP(char* buffer);
    std::string GetMappedIp(const pcpp::IPv4Address& ipKey);

    unsigned mSeed;
    std::default_random_engine mGenerator;
    std::uniform_int_distribution<int> mDistribution;

    bool mPreserveFlows;
    // Keeps track of each IP address that has been
    // mapped to a random IP address, allowing flow preservation.
    IpMap *mIpMap;
};

#endif
