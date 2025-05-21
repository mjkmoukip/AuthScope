

import logging
import ddddocr
from typing import Optional
class CaptchaSolver:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            self.ocr = ddddocr.DdddOcr(show_ad=False)
            self.logger.info("ddddocr OCR 引擎已初始化.")
        except Exception as e:
            self.logger.error(f"初始化 ddddocr 失败: {e}", exc_info=True)
            self.ocr = None

    async def solve(self, image_bytes: bytes) -> str | None:
        """
        尝试识别给定图像字节流中的验证码。
        :param image_bytes: 验证码图片的字节数据。
        :return: 识别出的验证码文本，如果失败则返回 None。
        """
        try:
            self.logger.debug("对验证码图片进行 OCR 识别.")
            captcha_text = self.ocr.classification(image_bytes)
            self.logger.info(f"验证码识别成功: {captcha_text}")
            return captcha_text.strip()
        except Exception as e:
            self.logger.error(f"处理验证码时发生错误: {e}", exc_info=True)
            return None