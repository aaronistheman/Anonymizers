#include "random_anonymizer.h"

RandomAnonymizer::RandomAnonymizer()
    : mSeed(std::chrono::system_clock::now().time_since_epoch().count())
    , mGenerator(mSeed)
    , mDistribution(0,255)
{
}

void generateRandomIP(char* buffer,
                       std::default_random_engine& generator,
                       std::uniform_int_distribution<int>& dist)
{
    int first = dist(generator);
    int second = dist(generator);
    int third = dist(generator);
    int fourth = dist(generator);
    sprintf(buffer, "%d.%d.%d.%d", first, second, third, fourth);
}

std::pair<std::string,std::string> RandomAnonymizer::map(
    const pcpp::IPv4Address& srcIp,
    const pcpp::IPv4Address& dstIp)
{
    char srcBuffer[16];
    generateRandomIP(srcBuffer,mGenerator,mDistribution);
    char dstBuffer[16];
    generateRandomIP(dstBuffer,mGenerator,mDistribution);
    return std::pair<std::string,std::string>(
        std::string(srcBuffer),std::string(dstBuffer));
}

