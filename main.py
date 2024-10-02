import dns.message
import dns.query
import dns.resolver
import dns.rcode
from dns.exception import DNSException
import socket
import re
import ssl
import threading
import struct
import logging
import json
from datetime import datetime
import os


class JSONRotatingLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        self.logger = logging.getLogger('dns_queries')
        self.logger.setLevel(logging.INFO)
        self.current_date = None
        self.file_handler = None
        self.update_file_handler()

    def update_file_handler(self):
        current_date = datetime.now().strftime('%Y-%m-%d')
        if current_date != self.current_date:
            if self.file_handler:
                self.logger.removeHandler(self.file_handler)
                self.file_handler.close()

            log_file = os.path.join(
                self.log_dir, f'{current_date}_dns_queries.json')
            self.file_handler = logging.FileHandler(log_file)
            self.logger.addHandler(self.file_handler)
            self.current_date = current_date

    def log(self, message):
        self.update_file_handler()
        self.logger.info(json.dumps(message))


class DNSOverTLSServer:
    def __init__(self, host="0.0.0.0", port=853, cert_file="server.crt", key_file="server.key"):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.block_list = self.load_block_list('block_list.txt')
        self.logger = JSONRotatingLogger()

    @staticmethod
    def load_block_list(filename):
        with open(filename, 'r') as file:
            return [re.compile(line.strip()) for line in file if line.strip()]

    def is_domain_blocked(self, domain):
        return any(pattern.search(domain) for pattern in self.block_list)

    @staticmethod
    def forward_dns_query(query, addr="1.1.1.1", port=853):
        try:
            return dns.query.tls(query, addr, port=port, timeout=5)
        except DNSException:
            return None

    def handle_dns_request(self, data, client_address):
        try:
            request = dns.message.from_wire(data)
            qname = str(request.question[0].name)
            qtype = dns.rdatatype.to_text(request.question[0].rdtype)

            if self.is_domain_blocked(qname):
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.NXDOMAIN)
                status = "BLOCKED"
                resolved_ip = None
            else:
                dns_response = self.forward_dns_query(request)
                if dns_response:
                    response = dns_response
                    status = "FORWARDED"
                    resolved_ip = self.extract_ip_from_response(response)
                else:
                    response = dns.message.make_response(request)
                    response.set_rcode(dns.rcode.SERVFAIL)
                    status = "SERVFAIL"
                    resolved_ip = None

            # Log the query
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "client_ip": client_address[0],
                "domain": qname,
                "query_type": qtype,
                "status": status,
                "resolved_ip": resolved_ip
            }
            self.logger.log(log_entry)

            return response.to_wire()
        except Exception as e:
            error_log = {
                "timestamp": datetime.now().isoformat(),
                "error": f"Error processing DNS request: {str(e)}",
                "client_ip": client_address[0]
            }
            self.logger.log(error_log)
            error_response = dns.message.make_response(dns.message.Message())
            error_response.set_rcode(dns.rcode.SERVFAIL)
            return error_response.to_wire()

    @staticmethod
    def extract_ip_from_response(response):
        for rrset in response.answer:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.A:
                    return rr.to_text()
                elif rr.rdtype == dns.rdatatype.AAAA:
                    return rr.to_text()
        return None

    def handle_client(self, client_socket, client_address):
        while True:
            try:
                length_data = client_socket.recv(2)
                if not length_data:
                    break
                length = struct.unpack('!H', length_data)[0]

                data = client_socket.recv(length)
                if not data:
                    break

                response = self.handle_dns_request(data, client_address)

                client_socket.sendall(struct.pack(
                    '!H', len(response)) + response)
            except ssl.SSLError as e:
                if e.errno == ssl.SSL_ERROR_WANT_READ:
                    continue
                else:
                    error_log = {
                        "timestamp": datetime.now().isoformat(),
                        "error": f"SSL Error handling client {client_address}: {str(e)}",
                        "client_ip": client_address[0]
                    }
                    self.logger.log(error_log)
                    break
            except Exception as e:
                error_log = {
                    "timestamp": datetime.now().isoformat(),
                    "error": f"Error handling client {client_address}: {str(e)}",
                    "client_ip": client_address[0]
                }
                self.logger.log(error_log)
                break
        client_socket.close()

    def run(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f"DNS-over-TLS Server running on {self.host}:{self.port}")

            with context.wrap_socket(sock, server_side=True) as secure_sock:
                while True:
                    client_socket, client_address = secure_sock.accept()
                    print(f"Accepted connection from {client_address}")
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, client_address))
                    client_thread.start()


if __name__ == "__main__":
    server = DNSOverTLSServer(
        cert_file="./tls/fullchain1.pem",
        key_file="./tls/privkey1.pem"
    )
    server.run()
