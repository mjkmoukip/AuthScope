import logging
import math
from typing import Dict, Optional, Tuple, List, Coroutine, Any
from playwright.async_api import Page, Locator, Error

class DomParser:
    """
    负责解析页面 DOM，根据预定义的算法和特征，查找登录相关的元素，
    包括用户名输入框、密码输入框、提交按钮以及验证码（如果存在）。
    主要利用元素的 ARIA Role、属性特征以及 Placeholder 文本进行匹配。
    """

    def __init__(self):
        """初始化 DomParser，设置日志记录器和特征集。"""
        self.logger = logging.getLogger(__name__)

        
        
        self.pwd_features_high = {'type': 'password'} 
        self.pwd_features_low = {'id': ['password', 'psw', 'pw', 'mima', 'pass']} 

        
        self.user_features_high = {
            'id': ['user'], 
            'name': ['account', 'name', 'login'] 
        }
        self.user_features_low = {'id': ['account', 'name', 'login']} 

        
        self.user_placeholder_features = {
            'placeholder': [
                '用户名', '账号', '会员名', '邮箱', '手机号', '学号', '工号', 
                'username', 'account', 'user',  'userid', 'login id' 
            ]
        }

        
        self.captcha_keywords = ['captcha', 'verify', 'code', 'vcode', 'checkcode', 'yzm', '校验码', '验证码']

        
        
        self.btn_typeMatch_features_high = {'text': ['登', 'log', 'go']} 
        self.btn_typeMatch_features_low = {'id_class': ['loginbtn', 'login-btn']} 

        
        self.btn_typeNotMatch_features_high = {
            'id': ['loginbtn', 'goBtn', 'loginbutton'], 
            'class': ['loginbtn', 'login-btn'] 
        }
        self.btn_typeNotMatch_features_low = {'text': ['登', 'log', 'go']} 

        
        self.btn_space_blacklist = ['foget', 'cancel', 'language'] 
        self.btn_space_whitelist = ['登', 'btn', 'button', 'submit', 'login', 'log in'] 
        self.btn_space_input_blacklist_condition = lambda html: '<input' in html and 'type="image"' not in html.lower()
        self.btn_space_whitelist_condition1 = lambda html: 'submit' in html.lower() and 'login' in html.lower()
        self.btn_space_whitelist_condition2 = lambda html: 'log in' in html.lower()

        
        self.captcha_img_selectors = [
            'img[id*="captcha"]', 'img[id*="verify"]', 'img[id*="code"]',
            'img[src*="captcha"]', 'img[src*="verify"]', 'img[src*="code"]',
            'img[alt*="captcha"]', 'img[alt*="验证码"]', 
            'img[title*="captcha"]', 'img[title*="验证码"]', 
        ]

    async def _feature_match(self, element: Locator, features: Dict[str, Any]) -> bool:
        """
        辅助函数：根据提供的特征字典匹配元素。
        :param element: Playwright Locator 对象。
        :param features: 特征字典，键是属性或匹配类型，值是期望的值或列表。
                        支持 'type', 'id', 'name', 'class', 'text', 'id_class', 'placeholder' (新增 ①)。
                        对于 'id', 'class', 'text', 'id_class', 'placeholder'，值可以是字符串列表，进行包含匹配。
                        对于 'type', 'id'(精准), 'name'(精准), 值是字符串，进行精准匹配。
                        对于 'name'(列表), 值是列表，进行精准匹配列表中的任意一个。
        :return: 如果匹配成功返回 True，否则 False。
        """
        try:
            for key, value in features.items():
                attr_value: Optional[str] = None
                match_found = False

                if key == 'type': 
                    attr_value = await element.get_attribute('type')
                    if attr_value and isinstance(value, str) and attr_value.lower() == value.lower():
                        match_found = True
                elif key == 'id': 
                    attr_value = await element.get_attribute('id')
                    if attr_value:
                        if isinstance(value, list): 
                            if any(v.lower() in attr_value.lower() for v in value):
                                match_found = True
                        elif isinstance(value, str): 
                            if attr_value.lower() == value.lower():
                                match_found = True
                elif key == 'name': 
                    attr_value = await element.get_attribute('name')
                    if attr_value:
                        if isinstance(value, list): 
                            if any(v.lower() == attr_value.lower() for v in value):
                                match_found = True
                        elif isinstance(value, str): 
                            if attr_value.lower() == value.lower():
                                match_found = True
                elif key == 'class': 
                    attr_value = await element.get_attribute('class')
                    if attr_value and isinstance(value, list):
                         if any(v.lower() in attr_value.lower() for v in value):
                            match_found = True
                elif key == 'text': 
                    text_content = await element.text_content() or "" 
                    tag_name = await element.evaluate('element => element.tagName', timeout=500) 
                    input_value = (await element.input_value(timeout=500) if tag_name and tag_name.lower() == 'input' else None) or "" 
                    if isinstance(value, list):
                        if any(v.lower() in text_content.lower() for v in value):
                             match_found = True
                        elif any(v.lower() in input_value.lower() for v in value):
                             match_found = True
                elif key == 'id_class': 
                     id_val = await element.get_attribute('id') or ""
                     class_val = await element.get_attribute('class') or ""
                     if isinstance(value, list):
                         if any(v.lower() in id_val.lower() for v in value):
                             match_found = True
                         elif any(v.lower() in class_val.lower() for v in value):
                             match_found = True
                
                elif key == 'placeholder': 
                    attr_value = await element.get_attribute('placeholder')
                    if attr_value and isinstance(value, list):
                        if any(v.lower() in attr_value.lower() for v in value):
                            match_found = True
                

                if match_found:
                    self.logger.debug(f"元素特征匹配成功: key='{key}', value='{value}'")
                    return True 

            
            return False

        except Error as e:
            
            self.logger.debug(f"特征匹配期间 Playwright 发生错误 (可能元素已失效): {e}")
            return False
        except Exception as e:
            self.logger.error(f"特征匹配期间发生意外错误: {e}", exc_info=True)
            return False

    async def _find_inputs(self, page: Page) -> Tuple[Optional[Locator], Optional[Locator]]:
        """
        查找用户名和密码输入框。
        优先使用 ARIA role 和标准属性定位，并检查 placeholder。
        :param page: Playwright Page 对象。
        :return: (username_locator, password_locator) 元组。
        """
        self.logger.info("开始查找用户名和密码输入框...")
        username_locator: Optional[Locator] = None
        password_locator: Optional[Locator] = None

        try:
            
            textboxes = page.get_by_role("textbox")
            passwords = page.locator('input[type="password"]')
            other_inputs = page.locator('input[type="text"]')
            potential_inputs = textboxes.or_(passwords).or_(other_inputs)
            

            
            all_inputs = await potential_inputs.all()
            self.logger.debug(f"找到 {len(all_inputs)} 个潜在的输入框元素 (通过 role, type)。")

            
            for element in all_inputs:
                
                try:
                    if not await element.is_visible(timeout=100): 
                        self.logger.debug("跳过不可见或已失效的输入框")
                        continue
                except Error: 
                    self.logger.debug("检查输入框可见性时出错，跳过")
                    continue

                is_password = False
                
                if password_locator is None: 
                    if await self._feature_match(element, self.pwd_features_high):
                        self.logger.info("通过高优先级特征 (type='password') 找到密码输入框。")
                        password_locator = element
                        is_password = True
                    elif await self._feature_match(element, self.pwd_features_low):
                        self.logger.info("通过低优先级特征 (id 包含关键字) 找到密码输入框。")
                        password_locator = element
                        is_password = True

                if is_password:
                    continue

                
                if username_locator is None:
                    if await self._feature_match(element, self.user_placeholder_features):
                        self.logger.info("通过 Placeholder 特征找到用户名输入框。")
                        username_locator = element
                    elif await self._feature_match(element, self.user_features_high):
                        self.logger.info("通过高优先级特征 (id/name) 找到用户名输入框。")
                        username_locator = element
                    elif await self._feature_match(element, self.user_features_low):
                        self.logger.info("通过低优先级特征 (id 包含关键字) 找到用户名输入框。")
                        username_locator = element

                
                if username_locator and password_locator:
                    self.logger.debug("已同时找到用户名和密码输入框，提前结束查找。")
                    break

            if not username_locator:
                self.logger.warning("未能明确找到用户名输入框。")
            if not password_locator:
                self.logger.warning("未能明确找到密码输入框。")

            return username_locator, password_locator

        except Error as e:
            self.logger.error(f"查找输入框时 Playwright 发生错误: {e}")
            return None, None
        except Exception as e:
            self.logger.error(f"查找输入框时发生意外错误: {e}", exc_info=True)
            return None, None

    
    async def _find_submit_button(self, page: Page, password_locator: Optional[Locator]) -> Optional[Locator]:
        """
        查找登录按钮。
        遵循算法 4-2 逻辑。
        :param page: Playwright Page 对象。
        :param password_locator: 已找到的密码输入框定位器，用于空间特征匹配。
        :return: 登录按钮的 Locator 或 None。
        """
        self.logger.info("开始查找登录按钮...")
        submit_locator: Optional[Locator] = None

        try:
            type_match_buttons = page.locator('button[type="button"], input[type="button"], button[type="submit"], input[type="submit"]')
            
            role_match_buttons = page.get_by_role("button")
            
            potential_buttons = type_match_buttons.or_(role_match_buttons)

            potential_buttons_list = await potential_buttons.all()
            self.logger.debug(f"找到 {len(potential_buttons_list)} 个潜在的按钮元素 (基于 type 或 role)。")

            
            self.logger.debug("按钮查找 Pass 1: 检查高优先级 TypeMatch 特征...")
            for element in potential_buttons_list:
                try:
                    if not await element.is_visible(timeout=100): continue
                    
                    tag_name = await element.evaluate('element => element.tagName', timeout=500) 
                    text_content = await element.text_content(timeout=500) or ""
                    input_value = (await element.input_value(timeout=500) if tag_name and tag_name.lower() == 'input' else "") or ""
                    full_text = (text_content + " " + input_value).lower()
                    if any(keyword in full_text for keyword in ['注册', 'cancel', 'reset', '清除', '找回密码', 'forgot']):
                        continue

                    
                    if await self._feature_match(element, self.btn_typeMatch_features_high):
                        self.logger.info("Pass 1: 通过高优先级 TypeMatch 特征找到提交按钮。")
                        submit_locator = element
                        break 

                except Error as e_inner:
                    self.logger.debug(f"Pass 1: 处理 TypeMatch 候选按钮时 Playwright 出错: {e_inner}")
                    continue 
                except Exception as e_general:
                    self.logger.warning(f"Pass 1: 处理 TypeMatch 候选按钮时发生意外错误: {e_general}", exc_info=True)
                    continue 

            
            if submit_locator is None:
                self.logger.debug("按钮查找 Pass 2: 检查低优先级 TypeMatch 特征...")
                for element in potential_buttons_list:
                    try:
                        
                        if not await element.is_visible(timeout=100): continue
                        tag_name = await element.evaluate('element => element.tagName', timeout=500) 
                        text_content = await element.text_content(timeout=500) or ""
                        input_value = (await element.input_value(timeout=500) if tag_name and tag_name.lower() == 'input' else "") or ""
                        full_text = (text_content + " " + input_value).lower()
                        if any(keyword in full_text for keyword in ['注册', 'cancel', 'reset', '清除', '找回密码', 'forgot']):
                            continue

                        
                        if await self._feature_match(element, self.btn_typeMatch_features_low):
                            self.logger.info("Pass 2: 通过低优先级 TypeMatch 特征找到提交按钮。")
                            submit_locator = element
                            break 

                    except Error as e_inner:
                        self.logger.debug(f"Pass 2: 处理 TypeMatch 候选按钮时 Playwright 出错: {e_inner}")
                        continue
                    except Exception as e_general:
                        self.logger.warning(f"Pass 2: 处理 TypeMatch 候选按钮时发生意外错误: {e_general}", exc_info=True)
                        continue 

            if submit_locator:
                    self.logger.info(f"最终确定提交按钮（基于 TypeMatch 特征）。")
                    return submit_locator

            
            self.logger.debug("未通过 TypeMatch 特征找到按钮，尝试 TypeNotMatch 特征...")
            
            if submit_locator is None:
                self.logger.debug("按钮查找 Pass 3: 检查高优先级 TypeNotMatch 特征...")
                
                
                all_elements_for_not_match = await page.locator('*').all() 
                potential_not_match_buttons = [el for el in all_elements_for_not_match if await el.is_visible(timeout=100) and not (await el.get_attribute('type') or "").lower() in ['button', 'submit']]

                for element in potential_not_match_buttons:
                    try:
                        if await self._feature_match(element, self.btn_typeNotMatch_features_high):
                            self.logger.info("Pass 3: 通过高优先级 TypeNotMatch 特征找到提交按钮。")
                            submit_locator = element
                            break
                    except Error as e: self.logger.debug(f"Pass 3 Error: {e}"); continue
                    except Exception as e: self.logger.warning(f"Pass 3 Exception: {e}"); continue

            
            if submit_locator is None:
                self.logger.debug("按钮查找 Pass 4: 检查低优先级 TypeNotMatch 特征...")
                for element in potential_not_match_buttons:
                     try:
                         if await self._feature_match(element, self.btn_typeNotMatch_features_low):
                             self.logger.info("Pass 4: 通过低优先级 TypeNotMatch 特征找到提交按钮。")
                             submit_locator = element
                             break
                     except Error as e: self.logger.debug(f"Pass 4 Error: {e}"); continue
                     except Exception as e: self.logger.warning(f"Pass 4 Exception: {e}"); continue

            if submit_locator:
                    self.logger.info(f"最终确定提交按钮（基于 TypeNotMatch 特征）。")
                    return submit_locator

            
            if not submit_locator and password_locator:
                self.logger.info("标准特征未找到按钮，尝试基于密码框的空间相对定位...")
                try:
                    
                    parent_form = password_locator.locator('xpath=ancestor::form[1]')
                    parent_div = password_locator.locator('xpath=ancestor::div[contains(@class, "login") or contains(@id, "login")][1]') 
                    search_area = parent_form if await parent_form.count() > 0 else (parent_div if await parent_div.count() > 0 else page)

                    
                    candidates = await search_area.locator('button, input[type="submit"], input[type="button"], a[role="button"], [onclick*="login"], [onclick*="submit"]').all()
                    self.logger.debug(f"空间定位：找到 {len(candidates)} 个候选元素在密码框附近区域。")

                    for candidate in candidates:
                        if not await candidate.is_visible(timeout=100): continue
                        html = (await candidate.evaluate('element => element.outerHTML', timeout=500) or "").lower()
                        
                        if any(bl_word in html for bl_word in self.btn_space_blacklist): continue
                        
                        if self.btn_space_input_blacklist_condition(html): continue
                        
                        passes_whitelist = any(wl_word in html for wl_word in self.btn_space_whitelist)
                        passes_cond1 = self.btn_space_whitelist_condition1(html)
                        passes_cond2 = self.btn_space_whitelist_condition2(html)

                        if passes_whitelist or passes_cond1 or passes_cond2:
                            self.logger.info("通过空间特征和关键字找到可能的提交按钮。")
                            submit_locator = candidate
                            break 

                except Error as e_space:
                    self.logger.warning(f"空间定位查找按钮时出错: {e_space}")
                except Exception as e_space_gen:
                     self.logger.error(f"空间定位查找按钮时发生意外错误: {e_space_gen}", exc_info=True)

            
            if submit_locator:
                    self.logger.info(f"最终确定提交按钮（可能基于空间特征）。")
                    return submit_locator
            else:
                    
                    self.logger.warning("未能找到明确的登录按钮。可能需要尝试发送 Enter 键。")
                    return None

        except Error as e:
            self.logger.error(f"查找提交按钮主流程时 Playwright 发生错误: {e}")
            return None
        except Exception as e:
            self.logger.error(f"查找提交按钮主流程时发生意外错误: {e}", exc_info=True)
            return None

    async def _find_captcha_elements(self, page: Page) -> Tuple[Optional[Locator], Optional[Locator]]:
        """
        尝试查找验证码图片和对应的输入框。
        输入框查找：使用 role="textbox" 或 type="text" 定位，
                    再匹配 id, name 或 placeholder 关键字。

        图片查找：
        1. 优先通过特定选择器查找 <img> 标签。
        2. 如果未找到，则查找页面上符合特定尺寸范围的可见元素，
           并优先选择靠近验证码输入框（如果已找到）的元素。

        :param page: Playwright Page 对象。
        :return: (captcha_image_locator, captcha_input_locator) 元组。
        """
        self.logger.info("开始尝试查找验证码相关元素...")
        captcha_image_locator: Optional[Locator] = None
        captcha_input_locator: Optional[Locator] = None 

        
        try:
            self.logger.debug("查找验证码图片 (基于 <img> 标签和属性)...")
            for selector in self.captcha_img_selectors:
                candidates = page.locator(selector)
                count = await candidates.count()
                if count > 0:
                    visible_candidates = []
                    all_candidates_list = await candidates.all()
                    for c in all_candidates_list:
                         try:
                             if await c.is_visible(timeout=300):
                                 visible_candidates.append(c)
                         except Error: 
                             self.logger.debug(f"检查图片 {selector} 可见性时元素失效，跳过。")
                             continue

                    if visible_candidates:
                         captcha_image_locator = visible_candidates[0] 
                         self.logger.info(f"找到可见的验证码图片，使用选择器: {selector}")
                         break 
            if not captcha_image_locator:
                self.logger.debug("未通过特定选择器找到 <img> 验证码图片。")
        except Error as e:
            self.logger.warning(f"查找验证码图片 (<img>) 时 Playwright 发生错误: {e}") 
        except Exception as e:
            self.logger.error(f"查找验证码图片 (<img>) 时发生意外错误: {e}", exc_info=True)

        
        try:
            self.logger.debug("查找验证码输入框...")
            potential_inputs = page.get_by_role("textbox").or_(page.locator('input[type="text"]'))
            input_list = await potential_inputs.all()
            self.logger.debug(f"找到 {len(input_list)} 个潜在的文本输入框 (通过 role='textbox' 或 type='text')，开始筛选验证码输入框...")

            for element in input_list:
                try:
                    
                    if not await element.is_visible(timeout=100): continue

                    
                    element_id = (await element.get_attribute('id', timeout=200) or "").lower()
                    element_name = (await element.get_attribute('name', timeout=200) or "").lower()
                    element_placeholder = (await element.get_attribute('placeholder', timeout=200) or "").lower()

                    
                    matched_keyword = None
                    for keyword in self.captcha_keywords:
                        if keyword in element_id or keyword in element_name or keyword in element_placeholder:
                            matched_keyword = keyword
                            break

                    if matched_keyword:
                        
                        el_type = (await element.get_attribute('type') or '').lower()
                        if el_type == 'password': continue 

                        self.logger.info(f"找到可能的验证码输入框 (ID='{element_id}', Name='{element_name}', Placeholder='{element_placeholder}'), 匹配关键字: '{matched_keyword}'")
                        captcha_input_locator = element
                        break 

                except Error as e_inner:
                     self.logger.debug(f"检查潜在验证码输入框时 Playwright 出错: {e_inner}")
                     continue
                except Exception as e_general:
                     self.logger.warning(f"检查潜在验证码输入框时发生意外错误: {e_general}", exc_info=True)
                     continue

            if not captcha_input_locator:
                 self.logger.debug("未通过关键字 (id/name/placeholder) 找到明确的验证码输入框。")

        except Error as e:
            self.logger.error(f"查找验证码输入框时 Playwright 发生错误: {e}")
        except Exception as e:
            self.logger.error(f"查找验证码输入框时发生意外错误: {e}", exc_info=True)

        if not captcha_image_locator and captcha_input_locator:
            self.logger.info("补充查找验证码图片：尝试查找符合尺寸和空间特征的可见元素...")
            best_candidate_locator: Optional[Locator] = None

            MIN_WIDTH = 40
            MAX_WIDTH = 250
            MIN_HEIGHT = 20
            MAX_HEIGHT = 100

            input_bbox = None
            if captcha_input_locator:
                try:
                    
                    input_bbox = await captcha_input_locator.bounding_box(timeout=500)
                    if not input_bbox:
                        self.logger.warning("已找到验证码输入框，但无法获取其边界框，将无法使用距离判断。")
                    else:
                         self.logger.debug(f"验证码输入框边界框: {input_bbox}")
                except Error as e:
                    self.logger.warning(f"获取验证码输入框边界框时出错: {e}，将无法使用距离判断。")

            try:
                candidate_selector = 'div, span, img, canvas, svg, i, p' 
                candidates = page.locator(candidate_selector)
                candidate_list = await candidates.all() 
                self.logger.debug(f"补充查找：找到 {len(candidate_list)} 个候选元素 (基于标签: {candidate_selector})。")

                input_center_x, input_center_y = None, None
                if input_bbox:
                    input_center_x = input_bbox['x'] + input_bbox['width'] / 2
                    input_center_y = input_bbox['y'] + input_bbox['height'] / 2

                for candidate in candidate_list:
                    try:
                        
                        if not await candidate.is_visible(timeout=100):
                            continue

                        bbox = await candidate.bounding_box(timeout=200)
                        if not bbox:
                            
                            continue 

                        w, h = bbox['width'], bbox['height']
                        if not (MIN_WIDTH <= w <= MAX_WIDTH and MIN_HEIGHT <= h <= MAX_HEIGHT):
                            
                            continue
                        
                        if input_bbox and input_center_x is not None and input_center_y is not None:
                            candidate_center_x = bbox['x'] + bbox['width'] / 2
                            candidate_center_y = bbox['y'] + bbox['height'] / 2

                            
                            if candidate_center_x < input_center_x or candidate_center_y < input_center_y:
                                continue

                        
                        tag = await candidate.evaluate('el => el.tagName.toLowerCase()', timeout=100)
                        pos_info = f"位于输入框右下方区域" if input_bbox else "位置不限（无输入框参考）"
                        self.logger.info(f"补充查找：找到符合条件的验证码图片候选者。标签={tag}, 尺寸={w:.0f}x{h:.0f}, {pos_info}")
                        best_candidate_locator = candidate 
                        break 

                    except Error as e_inner:
                        continue 
                    except Exception as e_general:
                        self.logger.warning(f"处理补充查找候选元素时发生意外错误: {e_general}", exc_info=True)
                        continue

            except Error as e:
                self.logger.error(f"补充查找验证码图片主流程时 Playwright 发生错误: {e}")
            except Exception as e:
                 self.logger.error(f"补充查找验证码图片主流程时发生意外错误: {e}", exc_info=True)

            
            if best_candidate_locator:
                captcha_image_locator = best_candidate_locator
            else:
                 self.logger.info("补充查找策略未能找到符合条件的验证码图片元素。")
        

        
        if captcha_image_locator and captcha_input_locator:
            self.logger.info("已找到验证码图片和输入框。")
        elif captcha_image_locator:
                self.logger.warning("找到了验证码图片，但未能找到对应的输入框。")
        elif captcha_input_locator:
                self.logger.warning("找到了可能的验证码输入框，但未能找到对应的图片。")
        else:
                self.logger.info("未找到验证码相关元素。")

        return captcha_image_locator, captcha_input_locator

    async def find_login_elements(self, page: Page) -> Optional[Dict[str, Optional[Locator]]]:
        """
        在给定的 Playwright Page 对象中查找登录相关的元素（用户名、密码、提交按钮、验证码）。
        这是核心协调方法，调用内部查找函数。

        :param page: Playwright Page 对象。
        :return: 包含定位器信息的字典，例如:
                 {
                     'username_locator': Optional[Locator], 
                     'password_locator': Optional[Locator], 
                     'submit_locator': Optional[Locator],
                     'captcha_image_locator': Optional[Locator],
                     'captcha_input_locator': Optional[Locator]
                 }
        """
        self.logger.info(f"开始在页面 {page.url} 上分析 DOM 以定位登录元素...")

        results: Dict[str, Optional[Locator]] = {
            'username_locator': None,
            'password_locator': None,
            'submit_locator': None,
            'captcha_image_locator': None,
            'captcha_input_locator': None
        }

        try:
            
            username_loc, password_loc = await self._find_inputs(page)

            results['username_locator'] = username_loc
            results['password_locator'] = password_loc

            if username_loc is None:
                 self.logger.warning("find_login_elements: 未能找到用户名输入框。")
            else:
                 self.logger.info("find_login_elements: 成功定位用户名输入框。")

            if password_loc is None:
                 self.logger.warning("find_login_elements: 未能找到密码输入框。")
            else:
                 self.logger.info("find_login_elements: 成功定位密码输入框。")

            
            submit_loc = await self._find_submit_button(page, results['password_locator'])
            results['submit_locator'] = submit_loc 
            if submit_loc:
                self.logger.info("find_login_elements: 成功定位提交按钮。")
            else:
                self.logger.warning("find_login_elements: 未找到提交按钮，后续可能尝试发送 Enter 键。")

            
            captcha_img_loc, captcha_input_loc = await self._find_captcha_elements(page)
            results['captcha_image_locator'] = captcha_img_loc 
            results['captcha_input_locator'] = captcha_input_loc 
            if captcha_img_loc or captcha_input_loc:
                    self.logger.info("find_login_elements: 完成验证码元素查找。")

            self.logger.info("登录元素分析完成。")
            return results

        except Exception as e:
            self.logger.error(f"在 find_login_elements 主流程中发生意外错误: {e}", exc_info=True)
            return results