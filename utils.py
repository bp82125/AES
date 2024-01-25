from re import sub
from textwrap import wrap

hex2bin_table = {'0': "0000",
                 '1': "0001",
                 '2': "0010",
                 '3': "0011",
                 '4': "0100",
                 '5': "0101",
                 '6': "0110",
                 '7': "0111",
                 '8': "1000",
                 '9': "1001",
                 'a': "1010",
                 'b': "1011",
                 'c': "1100",
                 'd': "1101",
                 'e': "1110",
                 'f': "1111"}

bin2hex_table = {"0000": '0',
                 "0001": '1',
                 "0010": '2',
                 "0011": '3',
                 "0100": '4',
                 "0101": '5',
                 "0110": '6',
                 "0111": '7',
                 "1000": '8',
                 "1001": '9',
                 "1010": 'a',
                 "1011": 'b',
                 "1100": 'c',
                 "1101": 'd',
                 "1110": 'e',
                 "1111": 'f'}


def hex2bin(s: str) -> str:
    return "".join([hex2bin_table[ch] for ch in s])


def bin2hex(s: str) -> str:
    temp = []
    for i in range(0, len(s), 4):
        temp.append(s[i:i + 4])

    return "".join([bin2hex_table[substr] for substr in temp])


def bin2dec(s: str) -> int:
    return int(s, 2)


def dec2bin(n: int) -> str:
    bin_str = bin(n)[2:]
    zero2add = (4 - (len(bin_str) % 4)) % 4

    return "0" * zero2add + bin_str


def permute(s, table, base):
    return "".join([s[table[i] - 1] for i in range(0, base)])


def xor(s1: str, s2: str) -> str:
    return "".join([str(int(s1[i]) ^ int(s2[i])) for i in range(len(s1))])


def shift_left(s, offset) -> str:
    offset = offset % len(s)
    return s[offset:] + s[:offset]


def text_to_base128(s):
    hex_str = s.encode(encoding="ascii").hex()

    if len(hex_str) % 32 == 0:
        return hex_str

    padding_length = 32 - (len(hex_str) % 32)
    padded_str = hex_str + '0' * padding_length

    return padded_str


def base128_to_text(s):
    hex_str = sub(r'00(?=0*$)', '', s)
    return bytes.fromhex(hex_str).decode('ascii')


def reshape_1d_to_2d(arr, rows, cols):
    result = []
    for i in range(rows):
        row = []
        for j in range(cols):
            index = i * cols + j
            row.append(arr[index])
        result.append(row)

    return result


def base128_to_grids(s):
    wrapped_text = wrap(s, width=2)
    grids = []

    for i in range(0, len(wrapped_text), 16):
        temp = wrapped_text[i:i + 16]
        grids.append(reshape_1d_to_2d(temp, 4, 4))

    return grids


def flatten(arr):
    return [item for row in arr for item in row]


def grids_to_base128(grids):
    return "".join(flatten(flatten(grids)))


if __name__ == "__main__":
    a = text_to_base128("Love is the warmest color.")
    b = base128_to_grids(a)

    c = grids_to_base128(b)
    print(c)
