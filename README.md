# MYIDS
This project was for a Computer Security and Privacy assignment

We had to implement an IDS that would interact with real-worl networking technologies.
Our IDS had to perform the following 
- Anomaly detection
- Spoofed packets
- Unauthorized servers
- Sinkhole lookups
- ARP spoofing
- IIS worms, and
- NTP reflection DDoD

My code was written in C and includes a makefile. In order for it to compile correctly, you must install the libcap library from http://www.tcpdump.org/. The skeleton to the packet structures and main function were taken from the following URL http://www.tcpdump.org/pcap.html, and I would like to thank Tim Carstens for this great tutorial on packet sniffing. 
