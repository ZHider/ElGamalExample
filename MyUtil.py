import decimal
import functools
import math


def xor_ints(*args) -> int:
    """输入数个字节，返回数个字节异或后的结果"""
    return functools.reduce(lambda a, b: a ^ b, args)


def lshift_int(i: int) -> int:
    """将32位数据左移一位，新的最右侧用原先的最左侧填补"""
    # 0xFFFFFFFF：丢弃32位以上的数据
    return ((i << 1) & 0xFFFFFFFF) + (i >> 31)


def add_m(*arg: int) -> int:
    """2^32模加法"""
    result = functools.reduce(decimal.getcontext().add, arg)
    return int(result % 0xFFFFFFFF)


def concat_int(*arg) -> int:
    """字面意义上的拼接整数，最后的数出现在最低位"""
    return int(functools.reduce(lambda a, b: str(a) + str(b), arg))


def split_packets(_bytes) -> list:
    """输入一个bytes，分割为数个8byte的数组"""
    l = list()
    for i in range(0, int(math.ceil(len(_bytes) / 8))):
        l.append(_bytes[8 * i: min(8 * (i + 1), len(_bytes))])

    return l


def concat_packets(pkl: list) -> bytes:
    """输入信息列表，返回一个完整的字节"""
    result = bytearray(len(pkl * 8))

    for i in range(0, len(pkl)):
        result[8 * i: 8 * (i + 1)] = int(pkl[i]).to_bytes(8, 'big').strip(b'\x00')

    return result
