/*
 * eaproxy.cpp: proxies EAP packets across network interfaces
 * 
 * Allows proxying authentication traffic across a gateway that
 * doesn't know how to forward EAP packets. Will also proxy
 * 802.1Q-encapsulated EAP traffic.
 * 
 * Usage: eaproxy <interface 1> <interface 2>
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pcap.h>

#include <string>
#include <thread>

struct capture_interface
{
    std::string iface_name;
    
    pcap_t *pcap_handle = nullptr;
    static constexpr uint32_t max_packet_size = 65536;
    static constexpr uint32_t pcap_timeout_ms = 100;

    struct bpf_program compiled_filter;
    bool compile_successful = false;
    const char *filter_string = "(ether proto 0x888e) or (vlan and ether proto 0x888e)";

    capture_interface *output_interface = nullptr;

    capture_interface(const char *interface_name)
    {
        iface_name = std::string(interface_name);
    }

    bool init()
    {
        char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
        int err;

        pcap_handle = pcap_open_live(iface_name.c_str(),
                                     max_packet_size,
                                     1,  // promisc mode
                                     pcap_timeout_ms,
                                     errbuf);
        
        if (pcap_handle == nullptr)
        {
            fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
            return false;
        }

        if (errbuf[0] != 0)
        {
            fprintf(stderr, "pcap_open_live warning: %s\n", errbuf);
        }

        err = pcap_setdirection(pcap_handle, PCAP_D_IN);
        if (err != 0)
        {
            fprintf(stderr, "pcap_setdirection failed: %s\n",
                    pcap_geterr(pcap_handle));
            return false;
        }

        err = pcap_compile(pcap_handle,
                           &compiled_filter,
                           filter_string,
                           1,   // optimize
                           PCAP_NETMASK_UNKNOWN);

        if (err == -1)
        {
            fprintf(stderr, "pcap_compile failed: %s\n",
                    pcap_geterr(pcap_handle));
            return false;
        }

        err = pcap_setfilter(pcap_handle, &compiled_filter);
        pcap_freecode(&compiled_filter);

        if (err == -1)
        {
            fprintf(stderr, "pcap_setfilter failed: %s\n",
                    pcap_geterr(pcap_handle));
            return false;
        }

        return true;
    }

    void set_output_interface(capture_interface *iface)
    {
        output_interface = iface;
    }

    // called when a packet is captured
    void process_packet(const struct pcap_pkthdr *header,
                        const u_char *packet_data)
    {
        if (header->len != header->caplen)
        {
            fprintf(stderr, "%s: short packet (captured %d bytes of %d)\n",
                    iface_name.c_str(), header->caplen, header->len);
            return;
        }

        int bytes_written = pcap_inject(output_interface->pcap_handle,
                                        packet_data, header->len);
        // fprintf(stderr, "%s: forwarded %d bytes to %s\n",
        //         iface_name.c_str(), bytes_written, output_interface->iface_name.c_str());
    }

    // pcap callback
    static void pcap_callback(u_char *user_arg,
                              const struct pcap_pkthdr *header,
                              const u_char *packet_data)
    {
        capture_interface *iface = (capture_interface *) user_arg;
        iface->process_packet(header, packet_data);
    }

    // thread entry point
    void operator() ()
    {
        // fprintf(stderr, "capture thread for %s started\n", iface_name.c_str());
        pcap_loop(pcap_handle,
                  0,    // never return
                  pcap_callback,
                  (u_char *)this);
    }
};

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <interface 1> <interface 2>\n", argv[0]);
        exit(1);
    }

    capture_interface iface_1(argv[1]);
    capture_interface iface_2(argv[2]);

    if (iface_1.init() == false)
    {
        exit(1);
    }

    if (iface_2.init() == false)
    {
        exit(1);
    }

    iface_1.set_output_interface(&iface_2);
    iface_2.set_output_interface(&iface_1);

    std::thread thread_iface_1(iface_1);
    std::thread thread_iface_2(iface_2);

    thread_iface_1.join();
    thread_iface_2.join();

    return 0;
}
