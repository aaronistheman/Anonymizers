#include "pcap_truncator.h"

#include "Packet.h"
#include "PcapFileDevice.h"

void PcapTruncator::truncatePcap(
                         char* inputPcapFileName,
                         char* outputPcapFileName,
                         int numPackets)
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
        printf("Cannot open %s for reading\n",inputPcapFileName);
        return;
    }

    pcpp::PcapFileWriterDevice writer(outputPcapFileName);
    writer.open();
    pcpp::RawPacket rawPacket;
    unsigned int numPacketsWritten = 0;
    while (reader->getNextPacket(rawPacket)
        && numPacketsWritten < numPackets)
    {
        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);
        writer.writePacket(rawPacket);
        numPacketsWritten += 1;
    }

    // close the file reader, we don't need it anymore
    reader->close();
    writer.close();
}

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        fprintf(stderr,"Wrong number of arguments.\n");
        return 1;
    }
    char* inputPcapFileName = argv[1];
    char* outputPcapFileName = argv[2];
    int numPackets = std::atoi(argv[3]);
    PcapTruncator::truncatePcap(inputPcapFileName,
                                outputPcapFileName,
                                numPackets);
    return 0;
}
