

import logging
import asyncio
from typing import Optional, Dict, Any

from playwright.async_api import async_playwright, Page, Browser, Playwright, BrowserContext, Error as PlaywrightError

class BrowserManager:
    """
    管理 Playwright 浏览器实例的生命周期和配置。
    负责启动、关闭浏览器，并提供创建浏览器上下文和页面的接口。
    设计为异步操作，以支持并发扫描任务。
    """
    def __init__(self):
        """初始化 BrowserManager。"""
        self.logger = logging.getLogger(__name__)
        self._playwright_context_manager = async_playwright()
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self.logger.debug("浏览器管理器已初始化。")

    async def launch_browser(self, headless: bool = True, browser_type: str = 'chromium', **kwargs) -> Optional[Browser]:
        """
        异步启动 Playwright 并启动指定类型的浏览器实例。

        :param headless: 是否以无头模式运行浏览器，默认为 True。
        :param browser_type: 要启动的浏览器类型 ('chromium', 'firefox', 'webkit')，默认为 'chromium'。
        :param kwargs: 其他传递给 browser.launch() 的参数 (例如 proxy, timeout)。
        :return: 启动成功的 Playwright Browser 对象，如果失败则返回 None。
        """
        if self._browser and self._browser.is_connected():
            self.logger.warning("浏览器实例已存在且处于连接状态，将返回现有实例。")
            return self._browser

        try:
            self.logger.info("正在启动 Playwright...")
            
            self._playwright = await self._playwright_context_manager.__aenter__()
            self.logger.debug("Playwright 启动成功。")

            browser_launcher = getattr(self._playwright, browser_type, None)
            if not browser_launcher:
                self.logger.error(f"不支持的浏览器类型: {browser_type}")
                await self.shutdown_playwright() 
                return None

            self.logger.info(f"正在启动 {browser_type} 浏览器 ({'无头' if headless else '有头'})...")
            self._browser = await browser_launcher.launch(headless=headless, **kwargs)
            self.logger.info(f"{browser_type} 浏览器启动成功。")
            return self._browser

        except PlaywrightError as e:
            self.logger.error(f"启动浏览器或 Playwright 失败: {e}")
            await self.shutdown_playwright() 
            self._browser = None 
            return None
        except Exception as e:
            self.logger.error(f"启动浏览器期间发生意外错误: {e}", exc_info=True)
            await self.shutdown_playwright() 
            self._browser = None 
            return None

    async def create_new_context(self, options: Optional[Dict[str, Any]] = None) -> Optional[BrowserContext]:
        """
        在当前浏览器实例上创建一个新的浏览器上下文（BrowserContext）。
        上下文是独立的会话，拥有自己的 Cookie、存储等。

        :param options: 传递给 browser.new_context() 的选项字典。
                        例如: {'user_agent': '...', 'viewport': {'width': 1920, 'height': 1080},
                               'extra_http_headers': {'X-Forwarded-For': '127.0.0.1'}}
        :return: 创建的 BrowserContext 对象，如果浏览器未启动或创建失败则返回 None。
        """
        if not self._browser or not self._browser.is_connected():
            self.logger.error("浏览器未启动或未连接，无法创建新的上下文。")
            return None

        context_options = options or {} 
        try:
            self.logger.debug(f"正在创建新的浏览器上下文，选项: {context_options}")
            context = await self._browser.new_context(**context_options)
            self.logger.info("新的浏览器上下文创建成功。")
            return context
        except PlaywrightError as e:
            self.logger.error(f"创建浏览器上下文失败: {e}")
            return None
        except Exception as e:
            self.logger.error(f"创建浏览器上下文期间发生意外错误: {e}", exc_info=True)
            return None

    async def create_new_page(self, context: BrowserContext) -> Optional[Page]:
        """
        在指定的浏览器上下文中创建一个新的页面（标签页）。

        :param context: 要在其中创建页面的 BrowserContext 对象。
        :return: 创建的 Page 对象，如果上下文无效或创建失败则返回 None。
        """
        if not context:
            self.logger.error("提供的浏览器上下文无效，无法创建新页面。")
            return None

        try:
            self.logger.debug("正在创建新的页面...")
            page = await context.new_page()
            self.logger.info("新页面创建成功。")
            return page
        except PlaywrightError as e:
            
            self.logger.error(f"创建新页面失败: {e} (上下文可能已关闭?)")
            return None
        except Exception as e:
            self.logger.error(f"创建新页面期间发生意外错误: {e}", exc_info=True)
            return None

    async def close_browser(self):
        """异步关闭浏览器实例，但不关闭 Playwright 进程。"""
        if self._browser and self._browser.is_connected():
            self.logger.info("正在关闭浏览器实例...")
            try:
                await self._browser.close()
                self.logger.info("浏览器实例已关闭。")
            except PlaywrightError as e:
                self.logger.warning(f"关闭浏览器实例时遇到错误: {e}")
            except Exception as e:
                self.logger.warning(f"关闭浏览器实例期间发生意外错误: {e}", exc_info=True)
            finally:
                self._browser = None 
        else:
            self.logger.debug("浏览器实例未运行或未连接，无需关闭。")

    async def shutdown_playwright(self):
        """
        彻底关闭 Playwright 实例和相关进程。
        通常在应用程序退出时调用。
        会先尝试关闭浏览器（如果还开着）。
        """
        await self.close_browser() 

        if self._playwright:
            self.logger.info("正在关闭 Playwright...")
            try:
                
                await self._playwright_context_manager.__aexit__(None, None, None)
                self.logger.info("Playwright 已关闭。")
            except Exception as e:
                self.logger.warning(f"关闭 Playwright 时遇到错误: {e}", exc_info=True)
            finally:
                self._playwright = None
        else:
            self.logger.debug("Playwright 实例未运行，无需关闭。")
