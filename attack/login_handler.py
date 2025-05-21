

import logging
from typing import Dict, Optional, Tuple, List, Any, Union 
from playwright.async_api import Page, Locator, Response, Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError, Dialog
from enum import Enum, auto

from analyzer.dom_parser import DomParser
from attack.captcha_solver import CaptchaSolver

class LoginResult(Enum):
    SUCCESS = auto()
    NO_SUCCESS = auto()
    FAILURE_PASSWORD_INCORRECT = auto() 
    FAILURE_USERNAME_NOT_FOUND = auto() 
    FAILURE_CAPTCHA = auto()            
    FAILURE_ACCOUNT_LOCKED = auto()     
    FAILURE_UNKNOWN = auto()
    FAILURE_DIALOG = auto()            
    ERROR_INTERACTION_FAILED = auto()   
    ERROR_NO_NETWORK_REQUEST = auto()   

class LoginHandler:
    """
    封装了在 Web 页面上执行自动化登录尝试、处理验证码以及分析登录结果的核心逻辑。
    使用 Playwright 与页面进行交互，结合 DomParser 动态分析和 CaptchaSolver 验证码识别。
    """

    LOGIN_RESULT_KEYWORDS: Dict[LoginResult, List[str]] = {
        LoginResult.SUCCESS: [
            "成功", "success", "welcome", "欢迎"
        ],
        
        LoginResult.NO_SUCCESS: [
            "失败", "failed", "error", "错误","404","防火墙","警告"
        ],
        LoginResult.FAILURE_USERNAME_NOT_FOUND: [
            "用户名不存在", "账号不存在", "用户不存在", "帐号不存在", "用户未注册",
            "user not found", "account does not exist", "no such user"
        ],
        LoginResult.FAILURE_PASSWORD_INCORRECT: [
             "密码错误", "密码不正确", "incorrect password", "wrong password",
             "password error", "凭证无效", "invalid credential", "账号或密码错误",
             "用户名或密码错误", "账户或密码不正确"
        ],
        LoginResult.FAILURE_CAPTCHA: [
            "验证码错误", "验证码不正确", "captcha error", "verification code is wrong",
            "invalid code", "验证码失效"
        ],
        LoginResult.FAILURE_ACCOUNT_LOCKED: [
            "锁定", "locked", "限制", "forbidden", "冻结", "封禁", "次数过多",
            "尝试过多", "ip禁止", "ip限制", "后重试", "请重试", "后再试", "操作频繁",
            "too many"
        ]
    }
    

    def __init__(self, dom_parser: DomParser):
        """
        初始化 LoginHandler。

        :param dom_parser: DomParser 实例，用于在登录过程中动态分析页面（特别是查找验证码）。
        """
        self.dom_parser = dom_parser
        self.logger = logging.getLogger(__name__)
        self.logger.info("LoginHandler 初始化完成。")

    def _check_text_for_keywords(self, text: str, target_results: Union[LoginResult, List[LoginResult]]) -> Optional[LoginResult]:
        """
        检查给定文本（小写化处理）是否包含指定登录结果类型的关键字。

        :param text: 要检查的文本内容 (例如弹窗消息, 网络响应体, 页面内容)。
        :param target_results: 一个或多个 LoginResult 枚举成员，指定要查找哪些类型的关键字。
        :return: 如果找到匹配的关键字，返回对应的 LoginResult 枚举成员；否则返回 None。
                 如果提供了多个 target_results，按列表顺序找到第一个匹配的就返回。
        """
        if not text:
            return None

        text_lower = text.lower()
        if not isinstance(target_results, list):
            target_results = [target_results] 

        for result_type in target_results:
            
            keywords = self.LOGIN_RESULT_KEYWORDS.get(result_type, [])
            for keyword in keywords:
                if keyword in text_lower:
                    self.logger.debug(f"文本中找到关键字匹配: 类型={result_type.name}.")
                    
                    self.logger.debug(f"关键字: {keyword}")
                    return result_type
        return None
    

    async def attempt_login(self, page: Page, elements: Dict[str, Optional[Locator]], credential: Tuple[str, str], captcha_solver: Optional[CaptchaSolver] = None, dialog_judge: bool = False, manual_captcha_mode: bool = False) -> LoginResult:
        """
        尝试使用给定的凭据在页面上执行一次登录。
        包含填充表单、处理验证码（如果需要）、点击提交、监听网络请求和分析结果的完整流程。
        新增逻辑：如果首次点击无网络请求，会尝试重载验证码并重试最多2次。

        :param page: Playwright 的 Page 对象。
        :param elements: 初始页面分析定位到的元素字典 ('username_locator', 'password_locator', 'submit_locator', 'captcha_image_locator'?, 'captcha_input_locator'?)。
        :param credential: 包含用户名和密码的元组 (username, password)。
        :param captcha_solver: 可选的 CaptchaSolver 实例，用于识别验证码。
        : dialog_judge 弹窗判断 + manual_captcha_mode 手动验证码 
        :return: 一个 LoginResult 枚举值，表示登录尝试的结果。
        """

        self.logger.info(f"开始尝试登录，用户名: {credential[0]}")

        captured_responses: List[Response] = []
        captured_dialogs: List[Dialog] = [] 

        
        
        def handle_response(response: Response):
            self.logger.debug(f"捕获到网络响应: {response.request.method} {response.url} {response.status}")
            captured_responses.append(response)
        page.on("response", handle_response)

        
        def handle_dialog(dialog: Dialog):
            self.logger.info(f"捕获到弹窗: 类型={dialog.type}, 消息='{dialog.message}'")
            captured_dialogs.append(dialog)
        page.on("dialog", handle_dialog)

        max_captcha_retries = 2 
        captcha_retries_done = 0

        try:
            
            login_action_result, captcha_handled = await self._execute_login_steps(page, elements, credential, captcha_solver, is_retry=False, dialog_judge=dialog_judge, manual_captcha_mode=manual_captcha_mode)

            if login_action_result != LoginResult.SUCCESS: 
                self.logger.warning(f"初始登录操作步骤失败: {login_action_result.name}")
                return login_action_result 

            await page.wait_for_load_state('networkidle', timeout=3000)
            self.logger.debug("首次登录点击后")

            
            while not captured_responses and captcha_retries_done < max_captcha_retries:
                captcha_retries_done += 1
                self.logger.warning(f"第 {captcha_retries_done}/{max_captcha_retries} 次尝试：点击登录后未捕获到网络请求。假定验证码问题，尝试重载并重试。")

                
                captcha_image_locator = elements.get("captcha_image_locator")
                captcha_input_locator = elements.get("captcha_input_locator")

                if not captcha_image_locator or not captcha_input_locator:
                     self.logger.info("初始元素中缺少验证码图片或输入框，尝试动态查找...")
                     dynamic_elements_tuple = await self.dom_parser._find_captcha_elements(page) 
                     if dynamic_elements_tuple and len(dynamic_elements_tuple) == 2 and all(dynamic_elements_tuple):
                         new_captcha_image_locator, new_captcha_input_locator = dynamic_elements_tuple
                         elements["captcha_image_locator"] = new_captcha_image_locator
                         elements["captcha_input_locator"] = new_captcha_input_locator
                         captcha_image_locator = new_captcha_image_locator
                         captcha_input_locator = new_captcha_input_locator
                         self.logger.info("动态找到验证码元素。")
                     else:
                         self.logger.error("动态查找未能找到完整的验证码元素（图片和输入框），无法执行重载重试。")
                         break

                if not captcha_solver:
                    self.logger.warning("需要处理验证码，但缺少验证码求解器。无法执行重载重试。")
                    break

                
                reload_successful = await self.reload_captcha(page, captcha_image_locator)

                if reload_successful:
                    self.logger.info(f"验证码重载成功 (尝试次数 {captcha_retries_done})。重新执行登录步骤...")
                    
                    captured_responses.clear()
                    captured_dialogs.clear()

                    
                    login_action_result_retry, _ , dialog_judge_retry = await self._execute_login_steps(page, elements, credential, captcha_solver, is_retry=True, dialog_judge=dialog_judge, manual_captcha_mode=manual_captcha_mode)

                    if login_action_result_retry != LoginResult.SUCCESS:
                        self.logger.warning(f"重试登录操作失败 (尝试次数 {captcha_retries_done}): {login_action_result_retry.name}")
                        return login_action_result_retry

                    
                    try:
                        await page.wait_for_load_state('networkidle', timeout=5000) 
                        self.logger.debug(f"重试登录 {captcha_retries_done} 后，网络短暂空闲或等待超时。")
                    except PlaywrightTimeoutError:
                        self.logger.debug(f"重试 {captcha_retries_done} 后等待网络空闲超时，继续检查响应。")
                    except Exception as e:
                       self.logger.error(f"重试 {captcha_retries_done} 后等待页面状态时发生意外错误: {e}")

                    if captured_responses:
                        self.logger.info(f"重试 {captcha_retries_done} 后成功捕获到网络请求，跳出重试循环。")
                        break

                else:
                    self.logger.warning(f"验证码重载失败 (尝试次数 {captcha_retries_done})。")
                    break

            
            if not captured_responses:
                
                self.logger.error(f"在初始尝试及最多 {captcha_retries_done} 次验证码重载尝试后，仍然没有捕获到网络请求。")
                return LoginResult.ERROR_NO_NETWORK_REQUEST

            
            self.logger.info("开始分析登录结果...")
            analysis_result = await self._analyze_login_result(page, elements, captured_responses, captured_dialogs)
            self.logger.info(f"登录尝试分析完成，结果: {analysis_result.name}")
            return analysis_result

        except PlaywrightTimeoutError as e:
            self.logger.error(f"Playwright 操作超时: {e}")
            return LoginResult.ERROR_INTERACTION_FAILED
        except PlaywrightError as e:
            self.logger.error(f"Playwright 交互错误: {e}")
            return LoginResult.ERROR_INTERACTION_FAILED
        except Exception as e:
            self.logger.exception(f"处理登录尝试时发生未预料的错误: {e}") 
            return LoginResult.FAILURE_UNKNOWN

        finally:
            
            try:
                page.remove_listener("response", handle_response)
                page.remove_listener("dialog", handle_dialog)
                for dialog in captured_dialogs:
                    
                    if not dialog.is_dismissed():
                       await dialog.dismiss()
            except Exception as e:
                self.logger.warning(f"清理监听器或关闭对话框时发生意外错误: {e}")
            self.logger.debug("清理完成。") 

    async def _execute_login_steps(self, page: Page, elements: Dict[str, Optional[Locator]], credential: Tuple[str, str], captcha_solver: Optional[CaptchaSolver], is_retry: bool, dialog_judge: bool, manual_captcha_mode: bool) -> Tuple[LoginResult, bool]:
        """
        私有方法：执行填充表单、处理验证码（如果找到且需要）、点击提交按钮的操作。
        !!注意!!: 此方法基本保持原始逻辑，不添加额外的检查和超时。
        """
        username, password = credential
        username_locator = elements.get("username_locator")
        password_locator = elements.get("password_locator")
        submit_locator = elements.get("submit_locator")
        captcha_image_locator = elements.get("captcha_image_locator")
        captcha_input_locator = elements.get("captcha_input_locator")
        
        captcha_handled = False

        try:
            if dialog_judge:
                self.logger.debug("弹窗判断为True，点击按钮前默认执行Enter，关闭前一次登录的Enter")
                await page.keyboard.press("Enter")

            
            await username_locator.fill(username)
            await password_locator.fill(password)

            
            if captcha_solver and captcha_image_locator and captcha_input_locator:
                is_visible = False
                try:
                    is_visible = await captcha_image_locator.is_visible(timeout=1000) 
                except PlaywrightTimeoutError:
                    self.logger.debug("检查验证码图片可见性超时，认为不可见。")
                except PlaywrightError as e:
                    self.logger.warning(f"检查验证码图片可见性时出错: {e}, 认为不可见。")

                if is_visible:
                    self.logger.info("发现可见的验证码，尝试识别并填充。")
                    if manual_captcha_mode:
                        self.logger.debug("手动切换验证码模式，点击按钮前默认切换验证码")
                        await self.reload_captcha(page, captcha_image_locator)
                    image_bytes = await captcha_image_locator.screenshot() 
                    captcha_code = await captcha_solver.solve(image_bytes) 

                    if captcha_code:
                        self.logger.info(f"验证码识别结果: {captcha_code}")
                        await captcha_input_locator.fill(captcha_code) 
                        captcha_handled = True
                    else:
                        self.logger.warning("验证码求解器未能返回结果。")
                else:
                     
                     if is_retry:
                         self.logger.warning("重试时发现验证码元素，但验证码图片当前不可见。")
                     else:
                         self.logger.debug("验证码图片元素当前不可见，跳过处理。")
            elif captcha_solver and (captcha_image_locator or captcha_input_locator):
                 self.logger.warning("找到了部分验证码元素（图片或输入框），但缺少另一部分，无法处理。")

            

            self.logger.debug("点击提交按钮...")
            await submit_locator.click(timeout=5000) 
            self.logger.info("登录表单已填充并提交,默认等待服务器0.3s")
            await page.wait_for_timeout(300) 

            return LoginResult.SUCCESS, captcha_handled

        except PlaywrightTimeoutError as e:
            self.logger.error(f"定位或与登录元素交互超时: {e}")
            return LoginResult.FAILURE_DIALOG, captcha_handled
        
        except PlaywrightError as e:
            
            self.logger.error(f"与登录元素交互时发生 Playwright 错误: {e}")
            return LoginResult.ERROR_INTERACTION_FAILED, captcha_handled  
        except Exception as e:
            self.logger.exception(f"执行登录步骤时发生未预料的错误: {e}")
            return LoginResult.ERROR_INTERACTION_FAILED, captcha_handled

    async def _analyze_login_result(self, page: Page, original_elements: Dict[str, Optional[Locator]], responses: List[Response], dialogs: List[Dialog]) -> LoginResult:
        """
        私有方法：根据弹窗信息、DOM变化、网络请求和页面内容，分析登录尝试是成功还是失败。
        !!修改点!!: 使用 _check_text_for_keywords 并增加成功前的锁定检查。
        优先级：
        1. 弹窗明确信息 (使用关键字检查)
        2. DOM 元素消失 + 页面内容无锁定信息 (使用关键字检查) => Success
        3. DOM 元素消失 + 页面内容有锁定信息 (使用关键字检查) => Locked
        4. DOM 元素未消失 + 网络响应/弹窗(已处理)/页面内容有特定失败信息 (使用关键字检查) => Specific Failure
        5. DOM 元素未消失 + 无特定失败信息 => Default Failure (PwdIncorrect)
        6. 未知情况 => Unknown
        """
        self.logger.debug("开始分析登录结果...") 

        
        self.logger.debug(f"检查 {len(dialogs)} 个弹窗...")
        for dialog in dialogs:
            
            result = self._check_text_for_keywords(dialog.message, list(self.LOGIN_RESULT_KEYWORDS.keys()))
            if result:
                 self.logger.info(f"从弹窗消息 '{dialog.message[:100]}...' 判断登录结果: {result.name}")
                 return result
        self.logger.debug("弹窗未提供明确的登录结果信息。")

        
        self.logger.debug("检查关键登录元素是否消失...")
        elements_disappeared = False
        try:
            username_locator = original_elements.get("username_locator")
            password_locator = original_elements.get("password_locator")
            submit_locator = original_elements.get("submit_locator")

            if username_locator and password_locator and submit_locator:
                
                visible_checks = []
                try:
                    visible_checks.append(await username_locator.is_visible(timeout=500))
                except (PlaywrightTimeoutError, PlaywrightError):
                    visible_checks.append(False)
                try:
                    visible_checks.append(await password_locator.is_visible(timeout=500))
                except (PlaywrightTimeoutError, PlaywrightError):
                    visible_checks.append(False)
                try:
                    visible_checks.append(await submit_locator.is_visible(timeout=500))
                except (PlaywrightTimeoutError, PlaywrightError):
                    visible_checks.append(False)

                if not any(visible_checks):
                    self.logger.info("用户名、密码输入框和提交按钮在尝试后均消失。") 
                    elements_disappeared = True

                    self.logger.debug("元素消失，检查当前页面内容是否存在失败信息...")
                    try:
                        current_content = await page.content() 
                        if current_content:
                            self.logger.debug(f"当前疑似成功的网络响应的内容长度: {len(current_content)}")
                            if len(current_content) > 3000:
                                self.logger.info("宽松判定，疑似成功(3000字符数以上)，跳过后续检查。")
                                return LoginResult.SUCCESS
                            
                        no_success_result = self._check_text_for_keywords(current_content, LoginResult.NO_SUCCESS)
                        if no_success_result:
                            self.logger.info("元素消失，但当前页面内容提示可能被失败。判断为: NO_SUCCESS")
                            return LoginResult.NO_SUCCESS
                        else:
                            self.logger.info("元素消失，且未在页面内容中发现锁定信息，判断为: SUCCESS")
                            return LoginResult.SUCCESS

                    except PlaywrightTimeoutError:
                         self.logger.warning("获取页面内容超时，无法执行锁定检查。按原逻辑判断为成功。")
                         return LoginResult.SUCCESS
                    except PlaywrightError as e_content:
                         self.logger.warning(f"获取页面内容检查锁定时出错: {e_content}。按原逻辑判断为成功。")
                         return LoginResult.SUCCESS
                    except Exception as e_content_unexp:
                         self.logger.warning(f"检查页面内容排除锁定时发生意外错误: {e_content_unexp}。按原逻辑判断为成功。")
                         return LoginResult.SUCCESS
                else:
                     self.logger.debug(f"至少有一个登录关键元素仍然可见 (检查结果: {visible_checks})。")
            else:
                self.logger.warning("原始元素字典中缺少关键登录元素定位器，无法通过 DOM 消失来判断成功。")

        except Exception as e_dom_check:
             self.logger.warning(f"检查登录元素可见性时发生意外错误: {e_dom_check}。")

        if not elements_disappeared:
            self.logger.debug("DOM 元素未消失或检查失败，开始分析网络响应以确定失败原因...")
            potential_login_responses = [r for r in responses if r.request.method == "POST" or "login" in r.url or "auth" in r.url]
            if not potential_login_responses:
                potential_login_responses = responses

            
            failure_types_to_check = [
                LoginResult.FAILURE_ACCOUNT_LOCKED,
                LoginResult.FAILURE_CAPTCHA,
                LoginResult.FAILURE_USERNAME_NOT_FOUND,
                LoginResult.FAILURE_PASSWORD_INCORRECT,
            ]

            for response in potential_login_responses:
                 try:
                     content = await response.text() 
                     result = self._check_text_for_keywords(content, failure_types_to_check)
                     if result:
                          self.logger.info(f"从网络响应 {response.url} ({response.status}) 内容判断登录失败: {result.name}")
                          return result 

                 except PlaywrightError as e:
                     self.logger.warning(f"获取响应 {response.url} 内容时出错: {e}")
                 except Exception as e:
                      self.logger.warning(f"分析响应 {response.url} 内容时发生意外错误: {e}")

            self.logger.debug("网络响应分析未找到明确的失败原因。") 

        
        if not elements_disappeared:
            self.logger.info("登录元素在尝试后仍然可见，且未从弹窗或网络响应中找到特定失败原因，默认判断为密码错误。")
            return LoginResult.FAILURE_PASSWORD_INCORRECT 

        
        self.logger.warning("所有分析规则均未能明确判断登录结果，默认返回未知失败。")
        return LoginResult.FAILURE_UNKNOWN

    async def reload_captcha(self, page: Page, captcha_image_locator: Optional[Locator]) -> bool:
        """
        尝试点击验证码图片以重新加载它，并验证图片内容是否变化。
        """
        if not captcha_image_locator:
            self.logger.warning("未提供验证码图片定位器，无法重载。")
            return False

        try:
            if not await captcha_image_locator.is_visible(timeout=2000):
                self.logger.warning("验证码图片当前不可见，无法点击重载。")
                return False

            self.logger.info("尝试获取初始验证码图片...")
            try:
                initial_bytes = await captcha_image_locator.screenshot(timeout=3000) 
            except (PlaywrightTimeoutError, PlaywrightError) as e:
                 self.logger.error(f"获取初始验证码图片失败: {e}")
                 initial_bytes = None

            self.logger.info("点击验证码图片进行重载...")
            await captcha_image_locator.click(timeout=3000) 

            
            await page.wait_for_timeout(300)

            if initial_bytes:
                try:
                    self.logger.debug("获取重载后的验证码图片...")
                    new_bytes = await captcha_image_locator.screenshot(timeout=3000)
                    if new_bytes != initial_bytes:
                        self.logger.info("验证码图片已成功重载 (内容变化)。")
                        return True
                    else:
                        self.logger.warning("点击后验证码图片内容未发生变化（或截图未捕获到变化）。假定刷新可能已触发。")
                        return True 
                except (PlaywrightTimeoutError, PlaywrightError) as e:
                    self.logger.error(f"重载后获取验证码图片失败: {e}")
                    return False 
            else:
                self.logger.info("已点击验证码图片，但因初始截图失败无法验证内容变化。假定刷新可能已触发。")
                return True 

        except PlaywrightTimeoutError as e:
            self.logger.error(f"查找或点击验证码图片超时: {e}")
            return False
        except PlaywrightError as e:
            self.logger.error(f"与验证码图片交互时发生 Playwright 错误: {e}")
            return False
        except Exception as e:
            self.logger.exception(f"重载验证码时发生未预料的错误: {e}")
            return False