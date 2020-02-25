#ifndef PCAP_TRUNCATOR_H
#define PCAP_TRUNCATOR_H

class PcapTruncator
{
public:
    static void truncatePcap(char* inputPcapFileName,
                             char* outputPcapFileName,
                             int numPackets);
};

#endif
