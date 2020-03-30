/**
 * Interface:
 * arg1: input file name
 * arg2: output file name
 * arg3: indicate which anonymization method:
 * - b = black-marker
 * - r = random
 * - rf = random but flow-preserving
 * arg4: (optional)
 * - if arg3 == b, then IP to replace src IPs with
 * arg5: (optional)
 * - if arg3 == b, then IP to replace dest IPs with
 */

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
               Anonymizer *anonymizer)
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
            auto newIps = anonymizer->Map(oldSrcIp,oldDstIp);
            auto newSrcIp = newIps.first;
            auto newDstIp = newIps.second;
            ipLayer->setSrcIpAddress(pcpp::IPv4Address(newSrcIp));
            ipLayer->setDstIpAddress(pcpp::IPv4Address(newDstIp));
        }
        else
            printf("Did not anonymize packet #%d\n",numPackets);
        writer.writePacket(*(parsedPacket.getRawPacket()));
        numPackets += 1;
    }

    // close the file reader, we don't need it anymore
    reader->close();
    writer.close();
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        fprintf(stderr,"Too few arguments.\n");
        return 1;
    }
    char *inputPcapFileName = argv[1];
    char *outputPcapFileName = argv[2];
    char *anonMethod = argv[3];
    Anonymizer *anonymizer;
    if (!strcmp(anonMethod,"r") or !strcmp(anonMethod,"rf"))
    {
        if (argc != 4)
        {
            fprintf(stderr,"Too many arguments.\n");
            return 1;
        }
    }
    if (!strcmp(anonMethod,"b"))
    {
        switch (argc)
        {
        case 4:
            anonymizer = new BlackMarkerAnonymizer();
            break;
        case 5:
            anonymizer = new BlackMarkerAnonymizer(argv[4]);
            break;
        case 6:
            anonymizer = new BlackMarkerAnonymizer(argv[4],argv[5]);
            break;
        default:
            fprintf(stderr,"Too many arguments.\n");
            return 1;
        }
    }
    else if (!strcmp(anonMethod,"r"))
        anonymizer = new RandomAnonymizer();
    else if (!strcmp(anonMethod,"rf"))
        anonymizer = new RandomAnonymizer(true);
    else
    {
        fprintf(stderr,"Invalid anonymization method: %s\n",anonMethod);
        return 1;
    }
    anonymize(inputPcapFileName, outputPcapFileName, anonymizer);
    delete anonymizer;
    return 0;
}
