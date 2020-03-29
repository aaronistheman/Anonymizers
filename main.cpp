#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <unordered_map>

#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"

#include "black_marker_anonymizer.h"
#include "random_anonymizer.h"

// Helpful source: the pcapplusplus tutorials

void anonymize(char* inputPcapFileName,
               char* outputPcapFileName,
               Anonymizer& anonymizer)
{
    pcpp::IFileReaderDevice* reader =
        pcpp::IFileReaderDevice::getReader(inputPcapFileName);

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        return;
    }
    
    if (!reader->open())
    {
        printf("Cannot open input.pcap for reading\n");
        return;
    }

    pcpp::PcapFileWriterDevice writer(outputPcapFileName);
    writer.open();
    pcpp::RawPacket rawPacket;
    unsigned int numPackets = 1;
    while (reader->getNextPacket(rawPacket))
    {
        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);
        // let's get the IPv4 layer
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer)
        {
            auto oldSrcIp = ipLayer->getSrcIpAddress();
            auto oldDstIp = ipLayer->getDstIpAddress();
            auto newIps = anonymizer.Map(oldSrcIp,oldDstIp);
            auto newSrcIp = newIps.first;
            auto newDstIp = newIps.second;
            ipLayer->setSrcIpAddress(pcpp::IPv4Address(newSrcIp));
            ipLayer->setDstIpAddress(pcpp::IPv4Address(newDstIp));
        }
        else
            printf("Did not anonymize packet #%d\n",numPackets);
        writer.writePacket(*(parsedPacket.getRawPacket()));
        numPackets += 1;
        // printf("Num packets read so far: %d\n",numPackets);
    }

    // close the file reader, we don't need it anymore
    reader->close();
    writer.close();
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        fprintf(stderr,"Wrong number of arguments.\n");
        return 1;
    }
    char* inputPcapFileName = argv[1];
    char* outputPcapFileName = argv[2];
    // BlackMarkerAnonymizer bma("10.149.10.150");
    // anonymize(inputPcapFileName, outputPcapFileName, bma);
    RandomAnonymizer ra(true);
    anonymize(inputPcapFileName, outputPcapFileName, ra);
    return 0;
}
