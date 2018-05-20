/*
 * eaproxy.cpp: forwards EAPoL packets across ethernet interfaces
 * 
 * Allows forwarding authentication traffic across a gateway that
 * doesn't know how to pass EAP packets. Will also proxy
 * 802.1Q-encapsulated EAP traffic.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pcap.h>
#include <libutil.h>
#include <signal.h>

#include <string>
#include <thread>

bool exit_on_success_packet = false;
char *interface_name_1 = nullptr;
char *interface_name_2 = nullptr;

bool pidfile_enable = false;
char *pidfile_path = nullptr;
struct pidfh *pidfile_handle = nullptr;

extern bool is_eapol_success(const uint8_t *data, uint32_t data_len);

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

        if (exit_on_success_packet)
        {
            if (is_eapol_success(packet_data, header->len))
            {
                // fprintf(stderr, "%s: forwarded EAPOL success message, exiting\n", iface_name.c_str());
                exit(0);
            }
        }
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

void usage_exit()
{
    fprintf(stderr, "usage: eaproxy [-p <pidfile>] [-e] <interface 1> <interface 2>\n");
    fprintf(stderr, "       -p [<pidfile>]  write PID to pidfile (default: /var/run/eaproxy.pid)\n");
    fprintf(stderr, "                       exits if PID file already exists\n");
    fprintf(stderr, "       -e              exits after forwarding an EAP success packet\n");
    exit(1);
}

void parse_cmdline(int argc, char **argv)
{
    int ch;

    while((ch = getopt(argc, argv, "ep::")) != -1)
    {
        switch(ch)
        {
            case 'e':
                exit_on_success_packet = true;
                break;
            
            case 'p':
                pidfile_enable = true;
                pidfile_path = optarg;
                break;

            default:
                usage_exit();
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 2)
    {
        usage_exit();
    }

    interface_name_1 = argv[0];
    interface_name_2 = argv[1];
}

void remove_pidfile()
{
    if (pidfile_handle)
    {
        pidfile_remove(pidfile_handle);
        pidfile_handle = nullptr;
    }
}

void on_signal(int /* sigtype */)
{
    remove_pidfile();
    exit(1);
}

void init_pidfile()
{
    if (!pidfile_enable)
    {
        return;
    }

    atexit(remove_pidfile);
    signal(SIGHUP, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    pid_t otherpid;
    pidfile_handle = pidfile_open(pidfile_path, 0600, &otherpid);
    if (pidfile_handle == nullptr)
    {
        if (errno == EEXIST)
        {
            fprintf(stderr, "eaproxy: already running (pid %d)\n", otherpid);
        } else {
            fprintf(stderr, "eaproxy: unable to create pid file %s: %s\n",
                    pidfile_path, strerror(errno));
        }

        exit(1);
    }

    atexit(remove_pidfile);
    pidfile_write(pidfile_handle);
}

int main(int argc, char **argv)
{
    parse_cmdline(argc, argv);
    init_pidfile();

    capture_interface iface_1(interface_name_1);
    capture_interface iface_2(interface_name_2);

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
