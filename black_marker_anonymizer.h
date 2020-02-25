#ifndef BLACK_MARKER_ANONYMIZER_H
#define BLACK_MARKER_ANONYMIZER_H

#include "anonymizer.h"

class BlackMarkerAnonymizer : public Anonymizer
{
public:
    // Arguments are what to map the src and dst IPs to.
    BlackMarkerAnonymizer(
        const std::string& srcIp = "0.0.0.0",
        const std::string& dstIp = "0.0.0.0");

    virtual std::pair<std::string,std::string> map(
            const pcpp::IPv4Address& ip1,
            const pcpp::IPv4Address& ip2);

private:
    std::string mSrcIp;
    std::string mDstIp;
};

#endif
