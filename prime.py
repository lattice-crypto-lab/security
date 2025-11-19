import random


def is_prime_miller_rabin(n, k=5):
    """Miller-Rabin 素性测试"""
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # 分解 n-1 = 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime_for_n(n, bits, count=1):
    """生成满足 q ≡ 1 mod 2n 的指定位数素数"""
    if bits < 2:
        raise ValueError("比特数至少为 2")

    result = []

    lower_bound = 2 ** (bits - 1)  # 最小比特范围
    k_mod = 2 * n  # 模数 2n
    value = (2**bits) - k_mod + 1

    while count > 0 and value > lower_bound:
        # 检测素数
        if is_prime_miller_rabin(value):
            result.append(value)
            count -= 1

        value -= k_mod

    return result


# 示例使用
n = 1024  # 多项式长度
bits = 16  # 素数 q 的比特数
q = generate_prime_for_n(n, bits, 10)
if len(q) != 0:
    print(f"生成的素数 q (比特数={bits}, 满足 q ≡ 1 mod {2*n}):")
    print(q)
else:
    print("没有满足要求的素数")

for i, v in enumerate(q):
    if i == 0:
        print(v,end=" ")
    else:
        print("*",end=" ")
        print(v,end=" ")
print()
