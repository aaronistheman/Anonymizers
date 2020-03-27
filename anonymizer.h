#ifndef ANONYMIZER_H
#define ANONYMIZER_H

#include <string>
#include <utility>

#include "IpAddress.h"

class Anonymizer
{
public:
    virtual std::pair<std::string,std::string> map(
                const pcpp::IPv4Address& srcIp,
                const pcpp::IPv4Address& dstIp) = 0;
};

#endif
