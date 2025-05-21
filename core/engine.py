

import asyncio
import logging
import hashlib
from typing import Dict, Optional, List, Tuple, Any, Set 

from analyzer.dom_parser import DomParser
from attack.login_handler import LoginHandler, LoginResult
from attack.credential_manager import CredentialManager
from attack.captcha_solver import CaptchaSolver
from utils.config_loader import ConfigLoader
from reporting.console_reporter import ConsoleReporter

from playwright.async_api import Page, Locator, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

class Engine:
    """
    AuthScope 的核心调度引擎。
    负责编排页面分析、登录尝试和结果报告的流程。
    !!! 注意：此类不再负责浏览器/上下文/页面的生命周期管理。!!!
    """

    def __init__(self, config_path: str = 'config/config.yaml', output_file: str = 'scan_report.txt'):
        """
        初始化引擎及所有必要的非浏览器依赖组件。

        Args:
            config_path (str): 配置文件的路径。
        """
        self.logger = logging.getLogger(__name__)
        self.logger.info("初始化 AuthScope 引擎...")

        
        self.config_loader = ConfigLoader(config_path=config_path)
        try:
            self.config = self.config_loader.load()
            self.logger.info(f"配置文件 '{config_path}' 加载成功。")
        except FileNotFoundError:
            self.logger.error(f"错误：配置文件 '{config_path}' 未找到。引擎无法继续初始化。")
            raise
        except Exception as e:
            self.logger.error(f"加载配置文件时发生错误: {e}", exc_info=True)
            raise

        self.dom_parser = DomParser()
        self.reporter = ConsoleReporter(filename=output_file)

        try:
            self.captcha_solver = CaptchaSolver()
            if self.captcha_solver:
                    self.logger.info("验证码识别器 CaptchaSolver 初始化成功。")
        except Exception as e:
            self.logger.error(f"初始化 CaptchaSolver 时发生意外错误: {e}", exc_info=True)
            self.captcha_solver = None

        cred_config = self.config.get('credentials', {})
        self.credential_manager = CredentialManager(
            user_dict_path=cred_config.get('user_dict'),
            pass_dict_path=cred_config.get('pass_dict'),
            universal_passwords=cred_config.get('universal_passwords', []),
            common_combinations=cred_config.get('common_combinations', [])
        )
        self.logger.info("凭证管理器 CredentialManager 初始化完成。")

        
        try:
            self.login_handler = LoginHandler(dom_parser=self.dom_parser)
            self.logger.info("登录处理器 (LoginHandler) 初始化完成。")
        except TypeError as e:
            self.logger.error(f"初始化 LoginHandler 失败: {e}", exc_info=True)
            raise RuntimeError("Engine 初始化失败：无法创建 LoginHandler") from e
        except Exception as e: 
            self.logger.error(f"初始化 LoginHandler 时发生未知错误: {e}", exc_info=True)
            raise RuntimeError("Engine 初始化失败：无法创建 LoginHandler") from e

        self.logger.info("AuthScope 引擎初始化完成 (不包括浏览器资源)。")

    
    async def run_scan(self, page: Page, target_url: str):
        """
        在给定的 Page 对象上对单个目标 URL 执行扫描流程。

        Args:
            page (Page): 一个由调用者（Worker）创建并管理的 Playwright Page 对象。
            target_url (str): 需要扫描的目标登录页面 URL。
        """
        self.logger.info(f"引擎开始在页面上处理目标: {target_url}")

        
        analysis_result: Optional[Dict[str, Optional[Locator]]] = None
        scan_error: Optional[str] = None
        found_weak_password: bool = False
        successful_credential: Optional[Tuple[str, str]] = None
        attempts_summary: List[Dict[str, Any]] = []
        initial_content_hash: str = ""

        try:
            try:
                try:
                        

                    browser_config = self.config.get('browser', {}) 
                    default_timeout = browser_config.get('timeout', 5000) 
                    
                    page.set_default_timeout(default_timeout)
                    self.logger.debug(f"页面默认超时设置为: {default_timeout}ms")

                    self.logger.info(f"导航到页面: {target_url}")
                    
                    await page.goto(target_url, wait_until='networkidle', timeout=default_timeout)
                    current_url = page.url
                    self.logger.info(f"页面加载完成，当前 URL: {current_url}")

                    
                    initial_content = await page.content()
                    initial_content_hash = hashlib.sha256(initial_content.encode('utf-8')).hexdigest()
                    self.logger.debug(f"获取到初始页面内容哈希: {initial_content_hash[:10]}...")

                except (PlaywrightError, PlaywrightTimeoutError) as nav_err:
                    scan_error = f"导航到 {target_url} 失败: {nav_err}"
                    self.logger.error(scan_error)
                    return 
                except Exception as nav_exc: 
                    scan_error = f"导航到 {target_url} 时发生意外错误: {nav_exc}"
                    self.logger.error(scan_error, exc_info=True)
                    return 

                
                analysis_result, analyze_error = await self._analyze_login_page(page)
                if analyze_error or not analysis_result:
                    self.logger.warning(f"页面分析失败或未找到关键元素: {analyze_error or '未找到足够元素'}")
                    scan_error = analyze_error or "未能识别到页面上的登录表单元素。"
                    return

                captcha_input_locator = analysis_result.get('captcha_input_locator')
                captcha_image_locator = analysis_result.get('captcha_image_locator')
                if captcha_input_locator and not captcha_image_locator:
                    scan_error = "分析错误：检测到验证码输入框，但未找到相应的验证码图片，无法继续尝试。"
                    self.logger.error(scan_error + f" (URL: {target_url})")
                    return

                
                can_proceed_to_attack = (
                    analysis_result.get('username_locator') and
                    analysis_result.get('password_locator') and
                    analysis_result.get('submit_locator')
                )
                if not can_proceed_to_attack:
                    scan_error = "分析完成，但缺少执行登录所需的核心元素（用户名、密码或提交按钮）。"
                    self.logger.warning(scan_error)
                    return 

                self.logger.info("核心登录元素已找到，准备执行登录尝试...")

                
                credentials_to_try = self._prepare_credentials()
                if not credentials_to_try:
                    scan_error = "无可用凭证进行测试（检查字典配置和文件）。"
                    self.logger.warning(scan_error)
                    return 

                
                found_weak_password, successful_credential, attempts_summary, loop_error = await self._execute_login_attempts(
                    page=page,
                    analysis_result=analysis_result,
                    credentials_to_try=credentials_to_try,
                    captcha_solver=self.captcha_solver
                )
                if loop_error:
                    scan_error = loop_error 

            except PlaywrightError as e:
                
                scan_error = f"扫描协调过程中发生 Playwright 错误: {e}"
                self.logger.error(scan_error, exc_info=True)
            except Exception as e:
                
                scan_error = f"发生意外的引擎层错误: {e}"
                self.logger.exception("扫描协调过程中捕获到未预料的异常:")

        
        except asyncio.CancelledError:
            
            scan_error = "任务被取消（可能由于超时）。"
            self.logger.warning(f"引擎任务处理 {target_url} 被取消，可能因为 Worker 设置的超时。")

        finally:
            
            self._handle_reporting(
                target_url=target_url,
                analysis_result=analysis_result,
                error=scan_error,
                found_weak_password=found_weak_password,
                successful_credential=successful_credential,
                attempts_summary=attempts_summary
            )

            self.logger.info(f"引擎处理目标 {target_url} 结束。")

    

    async def _analyze_login_page(self, page: Page) -> Tuple[Optional[Dict[str, Optional[Locator]]], Optional[str]]:
        """
        分析页面 DOM 以查找登录相关元素。
        """
        self.logger.info("开始分析页面 DOM 查找登录元素...")
        analysis_result: Optional[Dict[str, Optional[Locator]]] = None
        error_message: Optional[str] = None

        try:
            analysis_result = await self.dom_parser.find_login_elements(page)

            if analysis_result:
                found_elements = [k for k, v in analysis_result.items() if v is not None]
                self.logger.info(f"DOM 分析完成。找到的元素: {found_elements}")
                captcha_img = analysis_result.get('captcha_image_locator')
                captcha_input = analysis_result.get('captcha_input_locator')
                if captcha_img and captcha_input:
                    self.logger.info("已识别到潜在的验证码图片和输入框。")
                elif (captcha_img or captcha_input):
                     self.logger.warning(f"找到部分验证码元素，但可能不完整 (图片: {'有' if captcha_img else '无'}, 输入框: {'有' if captcha_input else '无'})。")
                else :
                    self.logger.info("未找到验证码相关元素（或 DomParser 未识别）。")
            elif hasattr(self.dom_parser, 'last_error') and self.dom_parser.last_error:
                 error_message = f"DOM 分析失败: {self.dom_parser.last_error}"
                 self.logger.error(error_message)
            else:
                 error_message = "DOM 分析未能识别到足够的登录元素。"
                 self.logger.warning(error_message)

        except PlaywrightError as e:
            error_message = f"DOM 分析过程中发生 Playwright 错误: {e}"
            self.logger.error(error_message, exc_info=True)
            analysis_result = None
        except Exception as e:
            error_message = f"DOM 分析过程中发生意外错误: {e}"
            self.logger.error(error_message, exc_info=True)
            analysis_result = None

        return analysis_result, error_message

    
    def _prepare_credentials(self) -> List[Tuple[str, str]]:
        """
        从 CredentialManager 获取并合并所有需要尝试的凭证。
        使用列表存储以尽量保留添加顺序，并在最后去重。
        """
        self.logger.info("准备待尝试的凭证列表 (保留顺序并去重)...")
        
        combined_credentials_list: List[Tuple[str, str]] = []

        
        if self.credential_manager._common_combinations:
            self.logger.debug(f"添加 {len(self.credential_manager._common_combinations)} 组常见组合...")
            combined_credentials_list.extend(self.credential_manager._common_combinations)

        
        dict_users = list(self.credential_manager.yield_users())
        dict_passwords = list(self.credential_manager.yield_passwords())
        if dict_users and dict_passwords:
            self.logger.debug(f"生成字典用户 ({len(dict_users)}) 和字典密码 ({len(dict_passwords)}) 的组合...")
            for user in dict_users:
                for password in dict_passwords:
                    combined_credentials_list.append((user, password)) 

        
        admin_user = 'admin'
        if self.credential_manager._universal_passwords:
            self.logger.debug(f"生成用户 '{admin_user}' 和万能密码 ({len(self.credential_manager._universal_passwords)}) 的组合...")
            for uni_pass in self.credential_manager._universal_passwords:
                combined_credentials_list.append((admin_user, uni_pass)) 
        else:
            self.logger.debug("未配置万能密码，跳过 admin 与万能密码的组合生成。")

        
        seen = set()
        unique_credentials: List[Tuple[str, str]] = []
        for cred in combined_credentials_list:
            if cred not in seen:
                unique_credentials.append(cred)
                seen.add(cred)

        self.logger.info(f"共准备了 {len(unique_credentials)} 组唯一的凭证组合进行尝试 (顺序已保留)。")

        return unique_credentials

    async def _execute_login_attempts(
        self,
        page: Page,
        analysis_result: Dict[str, Optional[Locator]],
        credentials_to_try: List[Tuple[str, str]],
        captcha_solver: Optional[CaptchaSolver]
    ) -> Tuple[bool, Optional[Tuple[str, str]], List[Dict[str, Any]], Optional[str]]:
        """
        执行登录尝试的核心循环。
        """
        found_weak_password = False
        successful_credential: Optional[Tuple[str, str]] = None
        attempts_summary: List[Dict[str, Any]] = []
        loop_error: Optional[str] = None
        invalid_usernames: Set[str] = set()

        stop_on_lockout = self.config.get('attack', {}).get('stop_on_lockout', True)
        max_captcha_retries_engine = self.config.get('attack', {}).get('max_captcha_retries_engine', 3)
        
        dialog_judge = False
        manual_captcha_mode = False
        i = 0

        
        while i < len(credentials_to_try):
            credential = credentials_to_try[i]
            username, password = credential

            if username in invalid_usernames:
                i += 1 
                continue

            self.logger.info(f"--- 第 {i+1}/{len(credentials_to_try)} 次尝试 --- 用户名: '{username}', 密码: '{password}'")

            login_result: Optional[LoginResult] = None
            captcha_retries_engine = 0

            
            while captcha_retries_engine <= max_captcha_retries_engine:
                login_result = await self.login_handler.attempt_login(
                    page=page,
                    elements=analysis_result,
                    credential=credential,
                    captcha_solver=captcha_solver,
                    dialog_judge=dialog_judge,
                    manual_captcha_mode=manual_captcha_mode
                )

                if login_result == LoginResult.FAILURE_DIALOG:
                    dialog_judge = True
                    continue
                    
                if login_result != LoginResult.FAILURE_CAPTCHA:
                    break
            
                captcha_retries_engine += 1
                if captcha_retries_engine <= max_captcha_retries_engine:
                    self.logger.warning(f"Engine: 检测到验证码失败 (LoginResult.FAILURE_CAPTCHA)，将进行 Engine 级别重试 {captcha_retries_engine}/{max_captcha_retries_engine}...")
                else:
                    self.logger.error(f"Engine: 验证码 Engine 级别重试达到最大次数 ({max_captcha_retries_engine})，凭证 {credential} 最终结果为验证码失败。")
                    self.logger.info("启动手动切换验证码模式.")
                    manual_captcha_mode = True
                    continue

            
            status_str = login_result.name if login_result else "未知状态"
            operation_error = None
            operational_errors = [
                LoginResult.ERROR_INTERACTION_FAILED,
                LoginResult.ERROR_NO_NETWORK_REQUEST,
            ]
            if login_result in operational_errors:
                operation_error = status_str
                status_str = "操作失败"

            summary_entry = {
                'credential': credential,
                'status': status_str,
                'operation_error': operation_error,
                'detection_error': None 
            }
            attempts_summary.append(summary_entry)

            log_detail = f"LoginResult: {login_result.name if login_result else 'N/A'}"
            if operation_error:
                 log_detail = f"操作失败详情: {operation_error}"
            if login_result == LoginResult.FAILURE_CAPTCHA and captcha_retries_engine > 0:
                 log_detail += f" (Engine 重试 {captcha_retries_engine-1} 次后)" if captcha_retries_engine <= max_captcha_retries_engine else f" (Engine 重试 {max_captcha_retries_engine} 次后最终失败)"

            self.logger.info(f"凭证 {credential} 最终尝试结果: {status_str} ({log_detail})")

            
            if login_result == LoginResult.SUCCESS:
                found_weak_password = True
                successful_credential = credential
                self.logger.critical(f"!!!!!! 发现弱口令 !!!!!! 用户名: {username}, 密码: {password} @ {page.url}")
                self.logger.info("发现弱口令，停止尝试。")
                break

            elif login_result == LoginResult.FAILURE_ACCOUNT_LOCKED:
                self.logger.warning(f"检测到账户可能被锁定: '{username}' (基于 LoginHandler 分析结果)")
                if stop_on_lockout:
                    self.logger.warning("根据配置 'stop_on_lockout'，停止尝试。")
                    break

            elif login_result == LoginResult.FAILURE_USERNAME_NOT_FOUND:
                 self.logger.warning(f"用户名 '{username}' 被标记为不存在。后续将跳过此用户名的其他尝试。")
                 invalid_usernames.add(username)

            elif login_result == LoginResult.NO_SUCCESS:
                self.logger.warning(f"登录失败后无法继续登录(跳转到其他页面等),暂时放弃该类型网站.")
                break

            
            if page.is_closed():
                loop_error = "登录尝试循环中止：页面已被意外关闭。"
                self.logger.error(loop_error)
                break

            if loop_error or login_result == LoginResult.SUCCESS or (login_result == LoginResult.FAILURE_ACCOUNT_LOCKED and stop_on_lockout):
                break

            
            i += 1

        if loop_error:
             self.logger.error(f"登录尝试循环因错误提前终止: {loop_error}")
        elif not found_weak_password and not loop_error:
             self.logger.info("所有凭证尝试完毕，未发现弱口令。")

        return found_weak_password, successful_credential, attempts_summary, loop_error

    
    def _handle_reporting(
        self,
        target_url: str,
        analysis_result: Optional[Dict[str, Optional[Locator]]],
        error: Optional[str],
        found_weak_password: bool,
        successful_credential: Optional[Tuple[str, str]],
        attempts_summary: List[Dict[str, Any]]
    ):
        """
        调用报告器生成并输出扫描结果。
        """
        self.logger.info(f"准备生成目标 {target_url} 的扫描报告...")
        try:
            analysis_result_repr = {}
            if analysis_result:
                for key, locator in analysis_result.items():
                    analysis_result_repr[key] = "存在" if locator else "未找到"

            self.reporter.report(
                 url=target_url,
                 analysis_result=analysis_result_repr,
                 error=error,
                 found_weak_password=found_weak_password,
                 successful_credential=successful_credential,
                 attempts_summary=attempts_summary
            )
        except Exception as report_err:
            self.logger.error(f"生成报告时出错: {report_err}", exc_info=True)