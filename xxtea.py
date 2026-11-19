# xxtea.py — minimal compat implementation (cocos2d-x style, length-word XXTEA)
# 供 cosjs.py 使用：xxtea.decrypt(cipher_bytes, key_str) -> plain_bytes
import struct

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _to_uint_array(data, inc_len=True):
    n = len(data) >> 2
    if len(data) & 3:
        n += 1
    pad = (n << 2) - len(data)
    v = list(struct.unpack('<%dI' % n, data + b'\0' * pad)) if n else []
    if inc_len:
        v.append(len(data) & MASK)
    return v


def _from_uint_array(v, inc_len=True):
    if not v:
        return b''
    # n = 去掉「长度 word」之后的字节数（与参考实现一致: (len(v)-1)<<2）
    n = (len(v) - 1) << 2
    cut = len(v) << 2
    if inc_len:
        m = v[-1]
        if (m < n - 3) or (m > n):
            cut = len(v) << 2
        else:
            cut = m
    return struct.pack('<%dI' % len(v), *[x & MASK for x in v])[:cut]


def _btea_encrypt(v, k):
    n = len(v) - 1
    if n < 1:
        return v
    rounds = 6 + 52 // (n + 1)
    s = 0
    z = v[n]
    while rounds > 0:
        s = (s + DELTA) & MASK
        e = (s >> 2) & 3
        for p in range(0, n):
            y = v[p + 1]
            v[p] = (v[p] + ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z)))) & MASK
            z = v[p]
        y = v[0]
        v[n] = (v[n] + ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(n & 3) ^ e] ^ z)))) & MASK
        z = v[n]
        rounds -= 1
    return v


def _btea_decrypt(v, k):
    n = len(v) - 1
    if n < 1:
        return v
    rounds = 6 + 52 // (n + 1)
    s = (rounds * DELTA) & MASK
    y = v[0]
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z)))) & MASK
            y = v[p]
        z = v[n]
        v[0] = (v[0] - ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(0 & 3) ^ e] ^ z)))) & MASK
        y = v[0]
        s = (s - DELTA) & MASK
    return v


def _key_words(key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    kb = (key + b'\0' * 16)[:16]
    return list(struct.unpack('<4I', kb))


def encrypt(data, key, padding=True):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not data:
        return b''
    v = _to_uint_array(data, inc_len=padding)
    k = _key_words(key)
    v = _btea_encrypt(v, k)
    return _from_uint_array(v, inc_len=False)


def _trim_known(buf):
    # gzip: 精确裁到 member 结尾（丢掉 XXTEA 的填充残留）
    if buf[:2] == b'\x1f\x8b':
        import zlib
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            d.decompress(buf)
            d.flush()
            consumed = len(buf) - len(d.unused_data)
            if 0 < consumed <= len(buf):
                return buf[:consumed]
        except Exception:
            pass
    # zip: 裁到 EOCD 结尾
    if buf[:2] == b'PK':
        idx = buf.rfind(b'PK\x05\x06')
        if idx >= 0 and idx + 22 <= len(buf):
            clen = int.from_bytes(buf[idx + 20:idx + 22], 'little')
            end = idx + 22 + clen
            if end <= len(buf):
                return buf[:end]
    return buf


def decrypt(data, key, padding=True):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not data:
        return b''
    v = _to_uint_array(data, inc_len=False)
    k = _key_words(key)
    v = _btea_decrypt(v, k)

    if not padding:
        return _from_uint_array(v, inc_len=False)

    # 先看是不是 gzip/zip（需要精确裁到 member 结尾）
    out = _from_uint_array(v, inc_len=False)
    trimmed = _trim_known(out)
    if len(trimmed) != len(out):
        return trimmed

    # 否则按 cocos 的长度 word 截断
    return _from_uint_array(v, inc_len=True)
