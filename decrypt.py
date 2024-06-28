import pyshark

packets = []
public_key = [155, 61, 100, 92, 135, 18, 250, 175, 149, 63, 99, 83, 55, 114, 250, 207]
current_private_key = public_key

serverAddress = ""
targetFilePath = ""

def get_key():
    key = []

    for i in range(16):
        key.append(current_private_key[i] ^ public_key[i])

    return key

def crypt_packet(data: bytearray):
    result = list(data)

    A = -99 * len(data)
    B = 2157
    key = get_key()

    for i in range(len(data)):
        result[i] = (data[i] ^ (A & 0xFF) ^ ((B >> 8) & 0xFF) ^ key[i & 0xF]) & 0xFF
        B *= 2171

    return result

def decode_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    for pkt in cap:
        if "ip" not in dir(pkt):
            continue

        if not (pkt.ip.src == serverAddress or pkt.ip.dst == serverAddress):
            continue
        
        if "tcp" in pkt and "payload" in dir(pkt.tcp):
            payload = pkt.tcp.payload
            if len(payload) == 0:
                continue

            data = list(bytearray.fromhex(payload.replace(":", ""))[32:])
            packetData = crypt_packet(data)
            global current_private_key

            if len(packetData) > 0 and packetData[7] != 0x00:
                temp = current_private_key
                current_private_key = public_key
                packetData_now = crypt_packet(data)
                current_private_key = temp
                packetData = packetData_now

            process(packetData, pkt.ip.src == serverAddress)

def process(packetData: list, is_from_server: bool):
    sid = int.from_bytes(packetData[0:2], byteorder="little")
    mid = int.from_bytes(packetData[2:4], byteorder="little")
    packetBody = packetData[24:]
    if (sid == 256 and mid == 18) or (sid == 32 and mid == 18):
        global current_private_key
        current_private_key = packetBody[:16]
    
    packets.append({ "sid": sid, "mid": mid, "body": packetBody, "is_from_server": is_from_server })

decode_pcap(targetFilePath)
# sid: XX, mid: XX, is_from_server: True/False
# BodyData: 0xaa 0xbb 0xcc 0xdd

texts = []
for packet in packets:
    headerText = f"sid: {packet["sid"]}, mid: {packet["mid"]}, is_from_server: {packet["is_from_server"]}"
    bodyText = "BodyData: " + " ".join([f"{hex(i)}" for i in packet["body"]])
    texts.append(headerText + "\n" + bodyText + "\n")

with open("decrypted-output.txt", "w") as f:
    f.writelines(texts)
    f.close()