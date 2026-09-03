# 从 netscan_tk 的品牌图标设计生成 Windows .ico 文件(32x32, 圆角透明)
import struct

from netscan_tk import icon_pixel

S = 32
xor = bytearray()
mask = bytearray()
for y in range(S - 1, -1, -1):  # ICO 像素自底向上
    bits = 0
    for x in range(S):
        col, opaque = icon_pixel(x, y, S)
        r, g, b = int(col[1:3], 16), int(col[3:5], 16), int(col[5:7], 16)
        xor += bytes((b, g, r, 255 if opaque else 0))
        if not opaque:
            bits |= 1 << (31 - x)
    mask += struct.pack(">I", bits)

header = struct.pack("<IiiHHIIiiII", 40, S, S * 2, 1, 32, 0,
                     len(xor) + len(mask), 0, 0, 0, 0)
data = header + bytes(xor) + bytes(mask)
ico = (struct.pack("<HHH", 0, 1, 1)
       + struct.pack("<BBBBHHII", S, S, 0, 0, 1, 32, len(data), 22)
       + data)
with open("icon.ico", "wb") as f:
    f.write(ico)
print(f"icon.ico written: {len(ico)} bytes")