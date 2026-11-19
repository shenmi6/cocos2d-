import gzip
import io
import os
import sys
from typing import Optional
from zipfile import BadZipFile, ZipFile
import xxtea
import logging


def get_logger(name=__name__):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


logger = get_logger(__name__)
VERSION_NUM = "v0.1"
PROGRAM_NAME = f"Cocos2d-x Lua Decrypt Tool {VERSION_NUM}"

LUA_MAGIC = b"\x1bLua"
LUAJIT_MAGIC = b"\x1bLJ"
GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = b"PK\x03\x04"

EXT_MAP = {
    "luac": ".luac",
    "luajit": ".luajit",
    "zip": ".zip",
    "lua": ".lua",
    "bin": ".bin",
}


def detect_kind(buf: bytes) -> str:
    """识别明文类型"""
    if buf.startswith(LUA_MAGIC):
        return "luac"
    if buf.startswith(LUAJIT_MAGIC):
        return "luajit"
    if buf.startswith(GZIP_MAGIC):
        return "gzip"
    if buf.startswith(ZIP_MAGIC):
        return "zip"

    head = buf[:4096]
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return "bin"
    for token in ("--", "function", "local", "return", "require", "module"):
        if token in text:
            return "lua"
    return "bin"


def parse_sign(sign_str) -> bytes:
    """sign 支持两种写法:
       普通字符串      -> "LJ"
       十六进制(非打印) -> "hex:4c4a0101ef"
    """
    if isinstance(sign_str, bytes):
        return sign_str
    if not sign_str:
        return b""
    if sign_str.startswith("hex:"):
        return bytes.fromhex(sign_str[4:])
    return sign_str.encode("utf-8")


def strip_sign(data: bytes, sign: bytes) -> bytes:
    """剥掉 cocos2d-x 的明文签名前缀 (setXXTEAKeyAndSign 里的 sign)"""
    if not sign:
        return data
    if data.startswith(sign):
        return data[len(sign):]
    idx = data[:64].find(sign)
    if idx >= 0:
        return data[idx + len(sign):]
    return data


def decrypt_buffer(data: bytes, key) -> Optional[bytes]:
    """XXTEA 解密 + 剥一层可能存在的 gzip"""
    out = xxtea.decrypt(data, key)
    if not out:
        return None
    if out.startswith(GZIP_MAGIC):
        try:
            out = gzip.decompress(out)
        except Exception:
            pass
    return out


def resolve_output(data: bytes, raw: bytes):
    """返回 (payload, kind)。如果解密结果不像任何已知格式，就看看原始数据是不是本来就明文。"""
    kind = detect_kind(data)
    if kind == "bin":
        kind0 = detect_kind(raw)
        if kind0 != "bin":
            return raw, kind0
    return data, kind


def export_data(
    luac_file_path: str, encryption_key_str: str, sign_str, output_file_path: str
) -> tuple:
    """解密单个文件"""
    logger.info("Starting export_data...")
    try:
        with open(luac_file_path, "rb"):
            pass
    except Exception as e:
        return "FILE_ERR", f"无法打开输入文件: {e}"

    raw = open(luac_file_path, "rb").read()
    sign = parse_sign(sign_str)
    body = strip_sign(raw, sign)
    logger.info(
        f"file={os.path.basename(luac_file_path)} size={len(raw)} "
        f"sign={len(raw) - len(body)}B key={encryption_key_str}"
    )

    out = decrypt_buffer(body, encryption_key_str)
    if not out:
        return "WRONG_KEY", "解密输出为空（key 错 / 不是 XXTEA 加密 / sign 错）"

    payload, kind = resolve_output(out, raw)
    logger.info(f"detected: {kind}")

    if kind == "zip" and not output_file_path.endswith(".zip"):
        output_file_path += ".zip"

    with open(output_file_path, "wb") as f:
        f.write(payload)
    logger.info(f"File exported: {output_file_path} ({len(payload)} bytes)")
    return "OK", ""


def process_dir(src_dir: str, out_dir: str, key: str, sign_str) -> tuple:
    """批量解密目录（保持相对路径）"""
    sign = parse_sign(sign_str)
    ok = 0
    fail = 0
    for root, _dirs, files in os.walk(src_dir):
        for name in files:
            src = os.path.join(root, name)
            rel = os.path.relpath(src, src_dir)
            base, _ext = os.path.splitext(rel)

            raw = open(src, "rb").read()
            body = strip_sign(raw, sign)
            out = decrypt_buffer(body, key)
            if not out:
                logger.warning(f"skip (decrypt failed): {rel}")
                fail += 1
                continue

            payload, kind = resolve_output(out, raw)
            ext = EXT_MAP.get(kind, ".bin")
            dst = os.path.join(out_dir, base + ext)
            parent = os.path.dirname(dst)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(dst, "wb") as f:
                f.write(payload)
            ok += 1

    return ok, fail


def main():
    # ========== 在这里直接改你的参数 ==========
    input_path = r"/storage/emulated/0/github/base/assets/src"   # 输入：单文件 或 目录
    encryption_key_str = ""                                      # XXTEA key（必填）
    sign_str = ""                                                # sign；无签名填 ""；非打印写 "hex:...."
    output_path = r"/storage/emulated/0/github/out"              # 输出：文件或目录
    # ========================================

    if not encryption_key_str:
        logger.error("请先在 main() 里填 encryption_key_str")
        sys.exit(-1)
    if not os.path.exists(input_path):
        logger.error(f"输入路径不存在: {input_path}")
        sys.exit(-1)

    logger.info(f"{PROGRAM_NAME}")
    logger.info(f"key = {encryption_key_str}   sign = {sign_str!r}")

    if os.path.isdir(input_path):
        ok, fail = process_dir(input_path, output_path, encryption_key_str, sign_str)
        logger.info(f"done: {ok} ok, {fail} failed -> {output_path}")
        sys.exit(0 if ok else -1)

    code, status = export_data(input_path, encryption_key_str, sign_str, output_path)
    if code != "OK":
        logger.error(f"{code}: {status}")
        sys.exit(-1)
    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()