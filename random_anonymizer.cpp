#include "random_anonymizer.h"

RandomAnonymizer::RandomAnonymizer(bool preserveFlows)
    // Source: http://www.cplusplus.com/reference/random/uniform_int_distribution/operator()/
    // construct a trivial random generator engine from a time-based seed:
    : mSeed(std::chrono::system_clock::now().time_since_epoch().count())
    , mGenerator(mSeed)
    , mDistribution(0,255)

    , mPreserveFlows(preserveFlows)
    , mIpMap(NULL)
{
    if (mPreserveFlows)
        mIpMap = new IpMap();
}

RandomAnonymizer::~RandomAnonymizer()
{
    delete mIpMap;
}

std::pair<std::string,std::string> RandomAnonymizer::Map(
    const pcpp::IPv4Address& srcIp,
    const pcpp::IPv4Address& dstIp)
{
    auto keyStr = srcIp.toString();
    if (mPreserveFlows)
    {
        std::string mappedSrcIp = GetMappedIp(srcIp);
        std::string mappedDstIp = GetMappedIp(dstIp);
        return std::pair<std::string,std::string>(mappedSrcIp,mappedDstIp);
    }
    else
    {
        char srcBuffer[16];
        char dstBuffer[16];
        GenerateRandomIP(srcBuffer);
        GenerateRandomIP(dstBuffer);
        return std::pair<std::string,std::string>(
            std::string(srcBuffer),std::string(dstBuffer));
    }
}

void RandomAnonymizer::GenerateRandomIP(char* buffer)
{
    int first = mDistribution(mGenerator);
    int second = mDistribution(mGenerator);
    int third = mDistribution(mGenerator);
    int fourth = mDistribution(mGenerator);
    sprintf(buffer, "%d.%d.%d.%d", first, second, third, fourth);
}

// ipKey is the IP address to map (i.e. to treat
// as a key).
std::string RandomAnonymizer::GetMappedIp(const pcpp::IPv4Address& ipKey)
{
    auto key = ipKey.toInt();

    if (mIpMap->find(key) == mIpMap->end())
    {
        // IP address is not already mapped; map it.
        char buffer[16];
        GenerateRandomIP(buffer);
        (*mIpMap)[key] = std::string(buffer);
    }
    return (*mIpMap)[key];
}

