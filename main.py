import binascii
import socket
import csv

final_result = False
server = ""
port = 0


# reset dns server address and port number
def reset_server():
    global server
    global port
    server = "1.1.1.1"
    # server = "198.41.0.4"
    port = 53
    # server = "127.0.0.1"
    # port = 1234


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


# build dns query
def build_message(type="A", address=""):
    ID = 43690  # 16-bit identifier (0-65535) # 43690 equals 'aaaa'

    QR = 0  # Query: 0, Response: 1     1bit
    OPCODE = 0  # 4bit
    AA = 0      # 1bit
    TC = 0      # 1bit
    RD = 1      # 1bit recursive:1 iterative: 0
    RA = 0      # 1bit
    Z = 0       # 3bit
    RCODE = 0   # 4bit

    query_params = str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)
    # save query parameters in 2 byte of hexadecimal and print in 4 digit
    query_params = "{:04x}".format(int(query_params, 2))

    QDCOUNT = 1  # questions           4bit
    ANCOUNT = 0  # answers             4bit
    NSCOUNT = 0  # authority records   4bit
    ARCOUNT = 0  # additional records  4bit

    # make complete message
    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QNAME is url split up by '.', preceded by int indicating length of part
    addr_parts = address.split(".")
    for part in addr_parts:
        # get length of each part of url
        addr_len = "{:02x}".format(len(part))
        # get hexadecimal representation of url
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00"  # Terminating bit for QNAME

    # Type of request
    QTYPE = get_type(type)
    message += QTYPE

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message

# parse message to find ip address
def decode_message(message):
    global final_result
    global server

    res = []
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20] # authority
    ARCOUNT = message[20:24] # additional

    # if there is answer part, finish searching
    if int(ANCOUNT) > 0:
        final_result = True

    # Question section
    QUESTION_SECTION_STARTS = 24
    question_parts = parse_parts(message, QUESTION_SECTION_STARTS, [])
    QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    # Answer section
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

    NUM_ANSWERS = int(ANCOUNT, 16) + int(NSCOUNT, 16) + int(ARCOUNT, 16)
    if NUM_ANSWERS > 0:

        for ANSWER_COUNT in range(NUM_ANSWERS):
            if (ANSWER_SECTION_STARTS < len(message)):
                ATYPE = message[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                RDLENGTH = int(message[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                RDDATA = message[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                if ATYPE == get_type("A"):
                    octets = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]
                    RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))

                else:
                    RDDATA_decoded = ".".join(
                        map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(RDDATA, 0, [])))

                ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)

            try:
                ATYPE
            except NameError:
                None
            else:
                # if there is answer part, return it
                if final_result:
                    res.append(RDDATA_decoded)
                # if there is not answer but there is ip of another dns server address to find, change dns server for next query
                elif not final_result and ATYPE == "0001":
                    server = RDDATA_decoded

    return "\n".join(res)


def get_type(type):
    types = ["ERROR", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTS", "HINFO", "MINFO",
             "MX", "TXT"]

    try:
        return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]
    except:
        return "None"


def parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]

    if len(part_len) == 0:
        return parts

    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])

    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return parse_parts(message, part_end, parts)


def search_cache(url):
    with open('cache.txt', mode='r') as f:
        csv_file = csv.reader(f)
        for row in csv_file:
            if row[0] == url:
                return row[1]


def send_req_get_res(url):
    print("Not Found in cache, create dns request...")

    message = build_message("A", url)
    print("Requested name address: \n" + url)

    # search iterative until find ip
    while True:
        print("DNS server: " + server)
        response = send_udp_message(message, server, port)
        responseIP = decode_message(response)

        if final_result:
            print("Response IP address: \n" + responseIP)
            break

    # add to cache
    with open("cache.txt", mode='a', newline='') as f:
        csvWriter = csv.writer(f)
        csvWriter.writerow([url, responseIP.split("\n")])
        print("Cache updated... \n")

    return responseIP



mode = int(input("Choose mode: \n1: url \t 2: csv\n"))

if mode == 1:
    url = input("Enter name address:\n")

    # search in cache
    ip = search_cache(url)
    # found in cache, so just print it
    if ip:
        print("Found in cache")
        print(url)
        print(ip)

    # not found in cache, so create dns message
    else:
        final_result = False
        reset_server()
        # send request and get response, then update cache
        responseIP = send_req_get_res(url)

# read urls from file
elif mode == 2:
    fileName = input("Enter file name:\n")
    # fileName = "urls.txt"
    with open(fileName) as f:
        urls = f.read().splitlines()

    with open("result.txt", mode='w', newline='') as f:
        for url in urls:

            # search in cache
            ip = search_cache(url)
            # found in cache, so just print it
            if ip:
                print("Found in cache")
                print(url)
                print(ip + "\n")
                csvWriter = csv.writer(f)
                csvWriter.writerow([url, ip])

            # not found in cache, so create dns message
            else:
                final_result = False
                reset_server()
                # send request and get response
                responseIP = send_req_get_res(url)
                csvWriter = csv.writer(f)
                csvWriter.writerow([url, responseIP.split("\n")])
    print("Result saved in file ...")