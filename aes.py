forward_sbox = [
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192],
    [183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21],
    [4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117],
    [9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132],
    [83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207],
    [208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168],
    [81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210],
    [205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115],
    [96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219],
    [224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121],
    [231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8],
    [186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138],
    [112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158],
    [225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223],
    [140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
]

reversed_sbox = [
    [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251],
    [124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203],
    [84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78],
    [8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37],
    [114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146],
    [108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132],
    [144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6],
    [208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107],
    [58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115],
    [150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110],
    [71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27],
    [252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244],
    [31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95],
    [96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239],
    [160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97],
    [23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]
]


def text_to_grids(s):
    res = []
    for i in range(len(s) // 16):
        b = s[i * 16: i * 16 + 16]
        grid = [[], [], [], []]
        for j in range(4):
            for k in range(4):
                grid[j].append(b[j + k * 4])
        res.append(grid)
    return res


def lookup_sbox(byte):
    x = byte >> 4
    y = byte & 15
    return forward_sbox[x][y]


def lookup_reversed_sbox(byte):
    x = byte >> 4
    y = byte & 15
    return reversed_sbox[x][y]


def expand_key(master_key, total_rounds):
    rcon = [[1, 0, 0, 0]]

    for _ in range(1, total_rounds):
        rcon.append([rcon[-1][0] * 2, 0, 0, 0])
        if rcon[-1][0] > 0x80:
            rcon[-1][0] ^= 0x11b

    key_grid = text_to_grids(master_key)[0]

    for round_aes in range(total_rounds):
        last_column = [row[-1] for row in key_grid]
        last_column_rotate_step = rotate_row_left(last_column)
        last_column_sbox_step = [lookup_sbox(b) for b in last_column_rotate_step]
        last_column_rcon_step = [
            last_column_sbox_step[i] ^ rcon[round_aes][i] for i in range(len(last_column_rotate_step))
        ]

        for r in range(4):
            key_grid[r] += bytes([last_column_rcon_step[r] ^ key_grid[r][round_aes * 4]])

        for i in range(len(key_grid)):
            for j in range(1, 4):
                key_grid[i] += bytes([key_grid[i][round_aes * 4 + j] ^ key_grid[i][round_aes * 4 + j + 3]])

    return key_grid


def rotate_row_left(row, n=1):
    return row[n:] + row[:n]


def multiply_by_2(v):
    s = v << 1
    s &= 0xff
    if (v & 128) != 0:
        s = s ^ 0x1b
    return s


def multiply_by_3(v):
    return multiply_by_2(v) ^ v


def mix_all_columns(grid):
    new_grid = [[], [], [], []]
    for i in range(4):
        col = [grid[j][i] for j in range(4)]
        col = mix_single_column(col)
        for k in range(4):
            new_grid[k].append(col[k])
    return new_grid


def mix_single_column(column):
    return [
        multiply_by_2(column[0]) ^ multiply_by_3(column[1]) ^ column[2] ^ column[3],
        multiply_by_2(column[1]) ^ multiply_by_3(column[2]) ^ column[3] ^ column[0],
        multiply_by_2(column[2]) ^ multiply_by_3(column[3]) ^ column[0] ^ column[1],
        multiply_by_2(column[3]) ^ multiply_by_3(column[0]) ^ column[1] ^ column[2],
    ]


def add_round_key(block_grid, key_grid):
    r = []
    for i in range(4):
        r.append([])
        for j in range(4):
            r[-1].append(block_grid[i][j] ^ key_grid[i][j])
    return r


def pad(text):
    offset = bytes(16 - len(text) % 16)

    if len(offset) != 16:
        text += offset

    return text


def extract_key_for_round(expanded_key, round_aes):
    return [row[round_aes * 4: round_aes * 4 + 4] for row in expanded_key]


def initial_encryption_round(grids, expanded_key):
    round_key = extract_key_for_round(expanded_key, 0)
    return [add_round_key(grid, round_key) for grid in grids]


def intermediate_encryption_round(grids, expanded_key, round_number):
    temp_grids = []

    for grid in grids:
        sub_bytes_step = [[lookup_sbox(val) for val in row] for row in grid]
        shifted_rows_step = [rotate_row_left(sub_bytes_step[i], i) for i in range(4)]
        mixed_columns_step = mix_all_columns(shifted_rows_step)

        round_key = extract_key_for_round(expanded_key, round_number)
        temp_grids.append(add_round_key(mixed_columns_step, round_key))

    return temp_grids


def final_encryption_round(grids, expanded_key):
    round_key = extract_key_for_round(expanded_key, 10)

    temp_grids = []
    for grid in grids:
        sub_bytes_step = [[lookup_sbox(val) for val in row] for row in grid]
        shifted_rows_step = [rotate_row_left(sub_bytes_step[i], i) for i in range(4)]
        temp_grids.append(add_round_key(shifted_rows_step, round_key))

    return temp_grids


def aes_encrypt(byte_plaintext: bytes, byte_key: bytes):
    padded_text = pad(byte_plaintext)
    padded_key = pad(byte_key)

    grids = text_to_grids(padded_text)
    expanded_key = expand_key(padded_key, 11)

    # Initial round
    round_grids = initial_encryption_round(grids, expanded_key)

    # 9 intermediate rounds
    for round_number in range(1, 10):
        round_grids = intermediate_encryption_round(round_grids, expanded_key, round_number)

    # Final round
    result_grids = final_encryption_round(round_grids, expanded_key)

    # Flatten
    int_stream = [grid[row][column] for grid in result_grids for column in range(4) for row in range(4)]

    return bytes(int_stream)


def initial_decryption_round(grids, expanded_key):
    round_key = extract_key_for_round(expanded_key, 10)

    temp_grids = []
    for grid in grids:
        add_sub_key_step = add_round_key(grid, round_key)
        shift_rows_step = [rotate_row_left(add_sub_key_step[i], -1 * i) for i in range(4)]
        sub_bytes_step = [[lookup_reversed_sbox(val) for val in row] for row in shift_rows_step]
        temp_grids.append(sub_bytes_step)

    return temp_grids


def intermediate_decryption_round(grids, expanded_key, round_number):
    temp_grids = []

    for grid in grids:
        add_sub_key_step = add_round_key(grid, extract_key_for_round(expanded_key, round_number))

        mix_column_step = mix_all_columns(add_sub_key_step)
        mix_column_step = mix_all_columns(mix_column_step)
        mix_column_step = mix_all_columns(mix_column_step)

        shift_rows_step = [rotate_row_left(mix_column_step[i], -1 * i) for i in range(4)]
        sub_bytes_step = [[lookup_reversed_sbox(val) for val in row] for row in shift_rows_step]

        temp_grids.append(sub_bytes_step)

    return temp_grids


def final_decryption_round(grids, expanded_key):
    round_key = extract_key_for_round(expanded_key, 0)
    return [add_round_key(grid, round_key) for grid in grids]


def aes_decrypt(byte_ciphertext: bytes, byte_key: bytes):
    padded_key = pad(byte_key)

    grids = text_to_grids(byte_ciphertext)
    expanded_key = expand_key(padded_key, 11)

    # Initial round
    round_grids = initial_decryption_round(grids, expanded_key)

    # 9 intermediate rounds
    for round_number in range(9, 0, -1):
        round_grids = intermediate_decryption_round(round_grids, expanded_key, round_number)

    # Final round
    round_grids = final_decryption_round(round_grids, expanded_key)

    # Flatten and remove padding
    int_stream = [grid[row][column] for grid in round_grids for column in range(4) for row in range(4)]
    return bytes(int_stream).replace(b'\x00', b'')


def encrypt(plain_text, master_key):
    byte_text = str.encode(plain_text)
    byte_key = str.encode(master_key)

    byte_ciphertext = aes_encrypt(byte_text, byte_key)

    return byte_ciphertext.hex()


def decrypt(cipher_text, master_key):
    byte_ciphertext = bytes.fromhex(cipher_text)
    byte_key = str.encode(master_key)

    byte_plaintext = aes_decrypt(byte_ciphertext, byte_key)

    return byte_plaintext.decode("utf-8")


if __name__ == "__main__":
    print("Choose your mode: 1 for encryption, 2 for decryption")
    mode = int(input())

    if mode == 1:
        print("Enter your text for encryption: ")
        pt = input()
        print("Enter your secret key (16 characters max): ")
        key = input()

        ct = encrypt(pt, key)
        print(f'Cipher text: {ct}')

    else:
        print("Enter your cipher text: ")
        ct = input()
        print("Enter your secret key (16 characters max): ")
        key = input()

        pt = decrypt(ct, key)
        print(f'Decrypted text: {pt}')

