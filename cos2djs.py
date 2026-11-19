import gzip
import io
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
VERSION_NUM = "v0.2"
EXE_FILE_NAME = f"jsc_pydecrypt_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f"JSC PyDecrypt Tool {VERSION_NUM}"


def export_data(
    jsc_file_path: str, encryption_key_str: str, output_file_path: str
) -> Optional[tuple]:
    """
    Function for decrypting JSC files
    """
    logger.info("Starting export_data...")

    # 移除 reversebox 的 check_file，改用原生判断文件是否存在
    try:
        with open(jsc_file_path, "rb"):
            pass
    except Exception as e:
        return "FILE_ERR", f"无法打开输入文件: {e}"

    jsc_file_data = open(jsc_file_path, "rb").read()
    logger.info(f"Decrypting with key = {encryption_key_str}")
    output_data = xxtea.decrypt(jsc_file_data, encryption_key_str)
    if len(output_data) == 0:
        return "WRONG_KEY", "Invalid encryption key!"
    is_gzip_file = True
    try:
        output_data = gzip.decompress(output_data)
        logger.info("IT IS a GZIP archive.")
    except gzip.BadGzipFile as error:
        logger.info("It's NOT a GZIP archive.")
        is_gzip_file = False
    if not is_gzip_file:
        try:
            zip_file = io.BytesIO(output_data)
            ZipFile(zip_file)
            output_file_path += ".zip"
            logger.info("IT IS a ZIP archive.")
        except BadZipFile as error:
            logger.info("It is NOT a ZIP archive.")
    js_file = open(output_file_path, "wb")
    js_file.write(output_data)
    js_file.close()
    logger.info(f"File exported: {output_file_path}")
    return "OK", ""


def main():
    # ========== 在这里直接改你的参数 ==========
    jsc_file_path = r"/storage/emulated/0/github/cocos2d-jsb.jsc"       # jsc输入文件路径
    encryption_key_str = "65dd8463-fe52-43"    # 解密密钥
    output_file_path = r"/storage/emulated/0/github/11.js"       # 输出文件路径
    # ========================================

    code, status = export_data(jsc_file_path, encryption_key_str, output_file_path)
    if code != "OK":
        logger.error(f"{code}: {status}")
        sys.exit(-1)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
