include /usr/local/etc/PcapPlusPlus.mk

all: anonymize truncate

truncate: pcap_truncator.cpp pcap_truncator.h
	g++ $(PCAPPP_INCLUDES) -g -c -o pcap_truncator.o pcap_truncator.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o truncate pcap_truncator.o $(PCAPPP_LIBS)

black_marker_anonymizer.o: black_marker_anonymizer.cpp black_marker_anonymizer.h anonymizer.h
	g++ $(PCAPPP_INCLUDES) -g -c -o black_marker_anonymizer.o black_marker_anonymizer.cpp

random_anonymizer.o: random_anonymizer.cpp random_anonymizer.h anonymizer.h
	g++ $(PCAPPP_INCLUDES) -g -c -o random_anonymizer.o random_anonymizer.cpp

MAIN_FILE := main.cpp
anonymize: $(MAIN_FILE) black_marker_anonymizer.o random_anonymizer.o
	g++ $(PCAPPP_INCLUDES) -g -c -o main.o $(MAIN_FILE)
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o anonymize main.o black_marker_anonymizer.o random_anonymizer.o $(PCAPPP_LIBS)

# Clean Target
clean:
	rm pcap_truncator.o truncate black_marker_anonymizer.o main.o anonymize
