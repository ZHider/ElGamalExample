import ElGamal
import MyUtil


# 原始数据
origin_text = '你好，Elgamal + SHA1 的世界，还有可怕的大素数原根！'
origin_text_encoded = origin_text.encode('utf-8')
origin_bytes = MyUtil.split_packets(origin_text_encoded)
origin_ints = [int.from_bytes(eight_bytes, 'big') for eight_bytes in origin_bytes]
print(f"原数据：text: {origin_text}, \n\tbytes: {origin_bytes}, int: {origin_ints}")

# 生成密钥对
key = ElGamal.gen_key_pair()
print(f"密钥对：{key}")

# 加密数据
cipher_pkts = [ElGamal.encrypt_packet(origin_int, key.pub_key) for origin_int in origin_ints]
print(f"数据加密后：packet: {cipher_pkts}, \n\t"
      f"text: {[int(cipher_pkt.c).to_bytes(ElGamal.PRIME_LENGTH, 'big') for cipher_pkt in cipher_pkts]}")

# 解密数据
plain_ints = [ElGamal.decrypt_packet(cipher_pkt, key) for cipher_pkt in cipher_pkts]
print(f"数据解密后：int: {plain_ints}, \n\t"
      f"text: {MyUtil.concat_packets(plain_ints).decode('utf-8')}")

# 签名数据
signed_pkts = [ElGamal.sign_packet(origin_eight_byte, key) for origin_eight_byte in origin_bytes]
print(f"数据签名后： {signed_pkts}")

# 校验数据
print(f"数据校验结果：{[ElGamal.verify_packet(signed_pkt, key.pub_key) for signed_pkt in signed_pkts]}")
