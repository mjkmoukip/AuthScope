
import logging
import sys

def setup_logger(level=logging.INFO):
    """配置全局日志记录器"""
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    logging.basicConfig(level=level,
                        format=log_format,
                        
                        handlers=[logging.StreamHandler(sys.stdout)]) 
    logging.getLogger("playwright").setLevel(logging.WARNING)
