import decimal
import Crypto.Random.random
import Crypto.Util.number


def gen_yk(g_or_y, rand, p):
    """
    计算一个用于传输的Y，或者生成最终密钥K。

    :param g_or_y: 模p的原根以生成用于传输的Y，或者对方传输过来的Y以生成最终密钥K。
    :param rand: 自己生成的随机数，rand∈[1, p-2]
    :param p: 模p，公开的一个大素数
    :return: 用于传输的密钥K中间生成数Y。
    """
    # 精度无限。
    return decimal.getcontext().power(g_or_y, rand, p)


def primitive_root(p):
    power = decimal.getcontext().power

    g = 1
    while power(g, 2, p) == 1 or power((p - 1) // 2, 2, p) == 1:
        g = Crypto.Random.random.randint(2, p - 1)

    return g
