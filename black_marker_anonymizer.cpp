#include "black_marker_anonymizer.h"

BlackMarkerAnonymizer::BlackMarkerAnonymizer(
    const std::string& srcIp, const std::string& dstIp)
    : mSrcIp(srcIp), mDstIp(dstIp)
{
}

std::pair<std::string,std::string> BlackMarkerAnonymizer::map(
    const pcpp::IPv4Address& ip1,
    const pcpp::IPv4Address& ip2)
{
    return std::pair<std::string,std::string>(mSrcIp, mDstIp);
}