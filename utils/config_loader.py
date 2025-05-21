
import yaml
import logging
import os
from typing import Dict, Any

DEFAULT_CONFIG_PATH = 'config/config.yaml' 

class ConfigLoader:
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self._config_cache: Dict[str, Any] | None = None 

    def load(self, force_reload: bool = False) -> Dict[str, Any]:
        """
        加载配置文件。如果已加载过，默认返回缓存结果。
        :param force_reload: 是否强制重新加载文件。
        :return: 配置字典。如果加载失败，返回空字典或抛出异常。
        """
        if self._config_cache is not None and not force_reload:
            self.logger.debug("返回缓存配置.")
            return self._config_cache

        self.logger.info(f"从: {self.config_path} 加载配置.")
        try:
            
            if not os.path.exists(self.config_path):
                 self.logger.error(f"Configuration file not found: {self.config_path}")
                 
                 
                 raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) 

            if not isinstance(config_data, dict):
                 self.logger.error("Configuration file content is not a valid dictionary.")
                 
                 config_data = {} 

            self._config_cache = config_data
            self.logger.info("配置加载成功.")

            
            

            return self._config_cache

        except yaml.YAMLError as e:
            self.logger.error(f"解析YAML配置文件 {self.config_path} 时发生错误: {e}", exc_info=True)
            
            raise ValueError(f"无效的YAML格式: {self.config_path}") from e
        except Exception as e:
            self.logger.error(f"加载配置时发生意外错误: {e}", exc_info=True)
            
            raise

    
    def get_setting(self, key_path: str, default: Any = None) -> Any:
         """
         安全地获取嵌套的配置项，支持点分隔路径。
         例如: get_setting('attack.timeout', 30)
         """
         config = self.load() 
         keys = key_path.split('.')
         value = config
         try:
             for key in keys:
                 if isinstance(value, dict):
                     value = value[key]
                 else:
                     
                     self.logger.warning(f"配置路径 '{key_path}' 中间键 '{key}' 未找到或不是字典.")
                     return default
             return value
         except KeyError:
             self.logger.warning(f"配置键 '{key_path}' 未找到. 返回默认值: {default}")
             return default
         except Exception as e:
             self.logger.error(f"访问配置键 '{key_path}' 时发生错误: {e}")
             return default

