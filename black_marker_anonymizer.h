#ifndef BLACK_MARKER_ANONYMIZER_H
#define BLACK_MARKER_ANONYMIZER_H

#include "anonymizer.h"

// Does not drop payload.
class BlackMarkerAnonymizer : public Anonymizer
{
public:
    // Arguments are what to map the src and dst IPs to.
    BlackMarkerAnonymizer(
        const std::string& srcIp = "0.0.0.0",
        const std::string& dstIp = "0.0.0.0");

    virtual std::pair<std::string,std::string> Map(
            const pcpp::IPv4Address&,
            const pcpp::IPv4Address&);

private:
    std::string mSrcIp;
    std::string mDstIp;
};

#endif
