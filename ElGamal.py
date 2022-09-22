import collections
import decimal
from math import ceil

import Crypto.Random.random
import Crypto.Util.number

import DiffieHellman
import SHA1

# 分组长度需要小于log2p，也就是分组长度(bit)需要小于 PRIME_N
PRIME_N = 100  # 模数（素数）长度，单位：bit
PRIME_LENGTH = int(ceil(PRIME_N / 8))  # 单个数据最多可能占多少字节
PACKET_LENGTH = 8  # 分组长度，单位：字节

key_pair = collections.namedtuple('key_pair', 'pub_key, pri_key')
pub_key = collections.namedtuple('pub_key', 'y, g, p')  # y: 传输密钥，g: 原根，p: 素模数
cipher_packet = collections.namedtuple('cipher_packet', 'ck, c')  # ck: DH协商密钥，c: 实质加密部分
signature_packet = collections.namedtuple('signature', 'm, r, s')  # 消息的数字签名，m表示原消息
p_and_g = collections.namedtuple('p_and_g', 'p, g') # 素数和其原根的组合

# 设置decimal计算精度为最高
decimal.setcontext(decimal.Context(prec=decimal.MAX_PREC))


def _gen_prime_and_root(N: int) -> p_and_g:
    """
    生成一个大素数和其原根。

    :param N: 要生成素数的位数(bit)
    :return: 二元组(p, g)
    """

    # 生成一个大素数 q，直接p是素数，其中 p = 2q + 1
    p, q = 4, 0
    while not Crypto.Util.number.isPrime(p):
        q = Crypto.Util.number.getPrime(N - 1)
        p = q * 2 + 1

    # 生成一个随机数 g，1 < g < p - 1，直到g^2 mod p 和 g^q mod p 都不等于 1
    g = 1
    while DiffieHellman.gen_yk(g, 2, p) == 1 or DiffieHellman.gen_yk(g, q, p) == 1:
        g = Crypto.Random.random.randint(2, p - 1)

    return p_and_g(p, g)


def gen_key_pair() -> key_pair:
    """生成一个新的密钥对（公钥、私钥）"""

    # 公钥中的 prime 素数
    p, g = _gen_prime_and_root(PRIME_N)
    # g需要和p-1互素，否则易受攻击
    while Crypto.Util.number.GCD(g, p - 1) != 1:
        p, g = _gen_prime_and_root(PRIME_N)

    # 私钥 - 一个随机数
    d = Crypto.Random.random.randint(2, p - 2)

    # 公钥其余部分
    y = DiffieHellman.gen_yk(g, d, p)
    pk = pub_key(y, g, p)

    return key_pair(pk, d)


def encrypt_packet(packet, pk: pub_key) -> cipher_packet:
    """
    加密一个packet。

    :param packet: 要加密的packet数据（二进制）
    :param pk: 对方的公钥
    :return: 一个可以发送的加密包
    """
    # 随机整数
    r = Crypto.Random.random.randint(2, pk.p - 2)
    # 真正最后会生成的一次性密钥
    K = DiffieHellman.gen_yk(pk.y, r, pk.p)

    return cipher_packet(
        DiffieHellman.gen_yk(pk.g, r, pk.p),
        (packet * K) % pk.p
    )


def decrypt_packet(cp: cipher_packet, kp: key_pair):
    """
    用私钥解密对应的cipher_packet

    :param cp: 要解密的包
    :param kp: 用来解密的密钥对
    :return: 被加密的明文数据
    """
    _pub_key: pub_key = kp.pub_key
    _pri_key_d = kp.pri_key
    # 对方意图生成的真正密钥
    K = DiffieHellman.gen_yk(cp.ck, _pri_key_d, _pub_key.p)
    # 解密
    return (cp.c * Crypto.Util.number.inverse(K, _pub_key.p)) % _pub_key.p


def sign_packet(packet: bytes, key: key_pair) -> signature_packet:
    """
    对一个packet签名

    :param packet: packet原始消息
    :param key: 签名方的密钥对
    :return: 一个经过签名的packet
    """
    # 计算packet的hash
    packet_hash = SHA1.sha1(packet)

    pk: pub_key = key.pub_key

    # k必须和p-1互质
    k = Crypto.Random.random.randint(2, pk.p - 2)
    while Crypto.Util.number.GCD(pk.p - 1, k) != 1:
        k = Crypto.Random.random.randint(2, pk.p - 2)
    # 计算其余部分
    r = DiffieHellman.gen_yk(pk.g, k, pk.p)
    s = ((packet_hash - key.pri_key * r) * Crypto.Util.number.inverse(k, pk.p - 1)) % (pk.p - 1)
    # 防止s是负数，方便后续计算
    # s在签名验证过程中做指数
    while s < 0:
        s += pk.p - 1

    return signature_packet(packet, r, s)


def verify_packet(sp: signature_packet, pk: pub_key) -> bool:
    """
    验证签名是否有效

    :param sp: 签名包
    :param pk: 对方的公钥
    :return: 签名是否正确
    """
    power = DiffieHellman.gen_yk
    packet_hash = SHA1.sha1(sp.m)

    return power(pk.g, packet_hash, pk.p) == (power(pk.y, sp.r, pk.p) * power(sp.r, sp.s, pk.p)) % pk.p
