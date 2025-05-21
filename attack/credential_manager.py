

import logging
import os
from typing import List, Tuple, Iterator, Optional

class CredentialManager:
    """
    管理用于认证攻击的凭证源。
    可以从文件加载用户和密码字典，并处理万能密码和优先组合。
    提供对不同凭证来源的迭代访问。
    """

    def __init__(self,
                 user_dict_path: Optional[str] = None,
                 pass_dict_path: Optional[str] = None,
                 universal_passwords: Optional[List[str]] = None,
                 common_combinations: Optional[List[List[str]]] = None):
        """
        初始化 CredentialManager。

        Args:
            user_dict_path (Optional[str]): 用户名字典文件的路径。
            pass_dict_path (Optional[str]): 密码字典文件的路径。
            universal_passwords (Optional[List[str]]): 万能密码列表。
            common_combinations (Optional[List[List[str]]]): 优先尝试的 [用户名, 密码] 组合列表。
        """
        self.logger = logging.getLogger(__name__)
        self._users: List[str] = []
        self._passwords: List[str] = []
        self._universal_passwords: List[str] = universal_passwords or []
        
        self._common_combinations: List[Tuple[str, str]] = [tuple(combo) for combo in common_combinations or [] if len(combo) == 2]

        
        if user_dict_path:
            if os.path.exists(user_dict_path):
                try:
                    with open(user_dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                        
                        self._users = [line.strip() for line in f if line.strip()]
                    self.logger.info(f"成功从 '{user_dict_path}' 加载 {len(self._users)} 个用户名。")
                except IOError as e:
                    self.logger.error(f"读取用户名字典 '{user_dict_path}' 时发生 IO 错误: {e}")
                except Exception as e:
                    self.logger.error(f"加载用户名字典 '{user_dict_path}' 时发生意外错误: {e}")
            else:
                self.logger.warning(f"用户名字典文件 '{user_dict_path}' 未找到。")
        else:
             self.logger.debug("未提供用户名字典路径，用户名列表为空。") 

        
        if pass_dict_path:
            if os.path.exists(pass_dict_path):
                try:
                    with open(pass_dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                        self._passwords = [line.strip() for line in f if line.strip()]
                    self.logger.info(f"成功从 '{pass_dict_path}' 加载 {len(self._passwords)} 个密码。")
                except IOError as e:
                    self.logger.error(f"读取密码字典 '{pass_dict_path}' 时发生 IO 错误: {e}")
                except Exception as e:
                     self.logger.error(f"加载密码字典 '{pass_dict_path}' 时发生意外错误: {e}")
            else:
                self.logger.warning(f"密码字典文件 '{pass_dict_path}' 未找到。")
        else:
            self.logger.debug("未提供密码字典路径，密码列表为空。") 

        
        

        self.logger.info(f"凭证管理器初始化完成：加载了 {len(self._users)} 用户, {len(self._passwords)} 密码, "
                         f"{len(self._universal_passwords)} 万能密码, {len(self._common_combinations)} 优先组合。")

    def yield_users(self) -> Iterator[str]:
        """
        生成用户名字典中的用户名。

        Yields:
            Iterator[str]: 一个用户名字符串。
        """
        if self._users:
            self.logger.debug(f"开始生成 {len(self._users)} 个字典用户名...")
            yield from self._users
            self.logger.debug("字典用户名生成完毕。")
        else:
            self.logger.debug("用户名字典为空，不生成用户名。")
            return iter([])

    def yield_passwords(self) -> Iterator[str]:
        """
        生成密码字典中的密码。

        Yields:
            Iterator[str]: 一个密码字符串。
        """
        if self._passwords:
            self.logger.debug(f"开始生成 {len(self._passwords)} 个字典密码...")
            yield from self._passwords
            self.logger.debug("字典密码生成完毕。")
        else:
            self.logger.debug("密码字典为空，不生成密码。")
            return iter([])
