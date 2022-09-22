import typing

import Crypto.Hash.SHA1
import Crypto.Util.Padding

import MyUtil

_bytes = typing.Union[bytes, bytearray]


def _pad(unpad_data: bytes) -> bytes:
    """SHA1 补位：1后0"""

    des_len = -1
    residue = (len(unpad_data) + 1) % 64
    if residue > 56:
        des_len = len(unpad_data) + 64 - (residue - 56)
    elif residue == 56:
        des_len = len(unpad_data) + 56 + 1
    elif residue < 56:
        des_len = len(unpad_data) + (56 - residue + 1)

    # 求数据总长度
    bit_len = (len(unpad_data) - 1) * 8 + unpad_data[-1].bit_length()
    return Crypto.Util.Padding.pad(unpad_data, des_len, style='iso7816') + bit_len.to_bytes(8, 'big')


def _ROTL(*args, exp=1) -> int:
    """一个左移+异或的函数"""

    # 如果输入的是bytes，那么转换成int
    if isinstance(args[0], bytes) or isinstance(args[0], bytearray):
        args = tuple(map(lambda b: int.from_bytes(b, 'big'), args))

    if len(args) > 1:
        # 多于一个参数则先异或
        _result = MyUtil.xor_ints(*args)
    else:
        _result = args[0]

    for _tmp in range(0, exp):
        # 左移
        _result = MyUtil.lshift_int(_result)

    return _result


def _extend_bytes(data: bytes) -> _bytes:
    """输入一个512bits/64字节的数据，将其扩张成80*32bits/80*4字节的分组"""

    def get_group(groups_data: _bytes, index: int) -> _bytes:
        """快捷的获取一组4字节数据"""
        offset = 4 * index
        return groups_data[offset: offset + 4]

    def set_group(groups_data: _bytes, index: int, input_data: _bytes):
        """快捷的设置一组4字节数据"""
        offset = 4 * index
        groups_data[offset: offset + 4] = input_data

    # 也就是 16*4 Bytes -> 80*4 Bytes，以4Byte作为单位
    result = bytearray(80 * 4)

    # Mt 0-15，直接照抄
    result[0: 16 * 4] = data

    # 其余的，进行ROTL1(Wt-3^Wt-8^Wt-14^Wt-16)
    for i in range(16, 80):
        _ROTL_data = _ROTL(
            get_group(result, i - 3),
            get_group(result, i - 8),
            get_group(result, i - 14),
            get_group(result, i - 16)
        )
        set_group(result, i, int.to_bytes(_ROTL_data, 4, 'big'))

    return result


def _rolling(extended_data: _bytes, H=None) -> tuple:
    """
    输入一个已经被扩展过的数据， 返回一个包含5个连接变量的元组

    :param extended_data: 被扩张过的80*4字节数据
    :param H: 上一步运算的连接变量（如果有）
    :return: tuple(H0, H1, H2, H3, H4)
    """

    def Kt(t: int) -> int:
        Kts = (
            0x5a827999,
            0x6ed9eba1,
            0x8f1bbcdc,
            0xca62c1d6
        )
        return Kts[t // 20]

    def Wt(t: int) -> int:
        return int.from_bytes(extended_data[4 * t: 4 * (t + 1)], 'big')

    def f(x, y, z) -> int:
        if 0 <= t <= 19:
            return (x & y) ^ (x & z)
        elif 20 <= t <= 39:
            return x ^ y ^ z
        elif 40 <= t <= 59:
            return (x & y) ^ (x & z) ^ (y & z)
        elif 60 <= t <= 79:
            return x ^ y ^ z

    # 初始连接变量
    if not H:
        H = (
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        )
    a, b, c, d, e = H

    for t in range(0, 80):
        T = MyUtil.add_m(_ROTL(a, exp=5), f(b, c, d), e, Kt(t), Wt(t))
        e = d
        d = c
        c = _ROTL(b, exp=30)
        b = a
        a = T

    return (
        MyUtil.add_m(a, H[0]),
        MyUtil.add_m(b, H[1]),
        MyUtil.add_m(c, H[2]),
        MyUtil.add_m(d, H[3]),
        MyUtil.add_m(e, H[4])
    )


def sha1(msg: bytes) -> int:

    padded_data = _pad(msg)
    H = None
    for i in range(0, len(padded_data) // 64):
        extended_data = _extend_bytes(padded_data[i * 64: (i+1) * 64])
        H = _rolling(extended_data, H)

    return MyUtil.concat_int(*H)
