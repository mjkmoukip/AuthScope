
import argparse
import logging
import os
import asyncio
import sys
from typing import List, Optional, Dict, Any, Tuple 
import datetime 

from core.engine import Engine
from utils.logger import setup_logger
from utils.config_loader import DEFAULT_CONFIG_PATH
from browser.browser_manager import BrowserManager 
from playwright.async_api import Page, BrowserContext, Error as PlaywrightError 

from reporting.console_reporter import ConsoleReporter

def _prepare_launch_options(browser_config: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """准备浏览器启动选项。"""
    launch_options: Dict[str, Any] = {}
    proxy_config = browser_config.get('proxy')
    if proxy_config and proxy_config.get('enabled') and proxy_config.get('server'):
        proxy_settings = {'server': proxy_config['server']}
        if proxy_config.get('username'): proxy_settings['username'] = proxy_config['username']
        if proxy_config.get('password'): proxy_settings['password'] = proxy_config['password']
        launch_options['proxy'] = proxy_settings
        logger.info(f"配置浏览器使用代理: {proxy_settings['server']}")
    return launch_options

def _prepare_context_options(browser_config: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
    """准备浏览器上下文选项。"""
    context_options: Dict[str, Any] = {}
    if 'user_agent' in browser_config:
         context_options['user_agent'] = browser_config['user_agent']
         logger.debug(f"设置 User-Agent: {browser_config['user_agent']}")
    if 'viewport' in browser_config and isinstance(browser_config['viewport'], dict):
         context_options['viewport'] = browser_config['viewport']
         logger.debug(f"设置视口: {browser_config['viewport']}")
    if 'headers' in browser_config and isinstance(browser_config['headers'], dict):
         
         context_options['extra_http_headers'] = {k: str(v) for k, v in browser_config['headers'].items()}
         logger.debug(f"设置自定义请求头: {context_options['extra_http_headers']}")
    if browser_config.get('ignore_https_errors', False):
         context_options['ignore_https_errors'] = True
         logger.warning("已配置忽略 HTTPS 证书错误。")
    return context_options

async def worker(
    worker_id: int,
    context: BrowserContext,
    engine: Engine,
    browser_manager: BrowserManager, 
    queue: asyncio.Queue
):
    """
    单个 Worker 协程，负责处理队列中的 URL 任务。
    每个 Worker 持有一个持久的 BrowserContext。
    """
    logger = logging.getLogger(__name__)
    logger.info(f"[Worker {worker_id}] 启动，使用 Context {context}") 

    while True:
        try:
            url = await queue.get()
            if url is None:
                logger.info(f"[Worker {worker_id}] 收到结束信号，退出。")
                queue.task_done()
                break

            logger.debug(f"[Worker {worker_id}] 开始处理任务: {url}")
            page: Optional[Page] = None
            task_timed_out = False 

            try:
                page = await browser_manager.create_new_page(context)
                if not page:
                    logger.error(f"[Worker {worker_id}] 无法为 URL '{url}' 创建页面，跳过此任务。")
                    queue.task_done()
                    continue

                
                task_timeout_seconds = 4 / 2 * 60.0
                try:
                    logger.info(f"[Worker {worker_id}] 为 URL '{url}' 设置任务超时: {task_timeout_seconds} 秒")
                    await asyncio.wait_for(
                        engine.run_scan(page, url),
                        timeout=task_timeout_seconds
                    )
                except asyncio.TimeoutError:
                    task_timed_out = True
                    logger.error(f"[Worker {worker_id}] 处理 URL {url} 超时 (超过 {task_timeout_seconds} 秒)，任务被终止。")

                except Exception as scan_err:
                    
                    logger.error(f"[Worker {worker_id}] 处理 URL {url} 时发生内部错误: {scan_err}", exc_info=True)

            except Exception as page_creation_err:
                 
                 logger.error(f"[Worker {worker_id}] 创建页面或执行扫描前发生错误 (URL: {url}): {page_creation_err}", exc_info=True)
            finally:
                if page and not page.is_closed():
                    try:
                        await page.close()
                        logger.debug(f"[Worker {worker_id}] 页面已为 URL '{url}' 关闭 (超时状态: {task_timed_out})。")
                    except PlaywrightError as page_close_err:
                        logger.warning(f"[Worker {worker_id}] 关闭页面 (URL: {url}) 时发生 Playwright 错误: {page_close_err}")
                    except Exception as page_close_generic_err:
                        logger.warning(f"[Worker {worker_id}] 关闭页面 (URL: {url}) 时发生未知错误: {page_close_generic_err}")
                
                queue.task_done()
                if task_timed_out:
                    logger.info(f"[Worker {worker_id}] URL '{url}' 的任务因超时而被标记为完成。")
                else:
                    logger.debug(f"[Worker {worker_id}] URL '{url}' 的任务已标记为完成。")

        except asyncio.CancelledError:
             logger.info(f"[Worker {worker_id}] 被取消。")
             break
        except Exception as queue_err:
             logger.error(f"[Worker {worker_id}] 在主循环中发生错误: {queue_err}", exc_info=True)
             await asyncio.sleep(1)

async def main():
    parser = argparse.ArgumentParser(description="AuthScope - Web 应用后台弱口令检测系统")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--urls", nargs='+', help="一个或多个目标 URL 进行扫描 (用空格分隔)")
    input_group.add_argument("-f", "--file", help="包含目标 URL 列表的文件路径 (每行一个 URL)")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help=f"指定配置文件的路径 (默认为: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("-v", "--verbose", action="store_true", help="启用详细日志记录 (DEBUG 级别)")
    parser.add_argument("-o", "--output", default="scan_report.txt", help="指定输出文件名 (默认为: scan_report.txt)")
    args = parser.parse_args()

    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(level=log_level)
    logger = logging.getLogger(__name__)
    logger.info("AuthScope 应用程序启动...")
    logger.debug(f"命令行参数: {args}")

    
    config_path = args.config
    if not os.path.exists(config_path):
        logger.error(f"错误：配置文件 '{config_path}' 未找到。")
        sys.exit(1)
    logger.info(f"使用配置文件: '{config_path}'")

    
    targets: List[str] = []
    if args.file:
        logger.info(f"从文件 '{args.file}' 读取目标 URL...")
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if not targets:
                logger.error(f"错误：文件 '{args.file}' 为空或只包含无效行。")
                sys.exit(1)
            logger.info(f"成功从文件加载 {len(targets)} 个目标 URL。")
        except FileNotFoundError:
            logger.error(f"错误：URL 文件 '{args.file}' 未找到。")
            sys.exit(1)
        except IOError as e:
            logger.error(f"读取 URL 文件 '{args.file}' 时发生 IO 错误: {e}")
            sys.exit(1)
    elif args.urls:
        targets = args.urls
        logger.info(f"从命令行接收 {len(targets)} 个目标 URL。")

    display_targets = targets[:5]
    logger.info(f"准备扫描以下目标 (最多显示前5个): {', '.join(display_targets)}{'...' if len(targets) > 5 else ''}")

    
    engine: Optional[Engine] = None
    browser_manager: Optional[BrowserManager] = None
    persistent_contexts: List[BrowserContext] = []
    browser_launched = False 
    reporter: Optional['ConsoleReporter'] = None 

    try:
        
        logger.debug("正在初始化扫描引擎 (加载配置)...")
        engine = Engine(config_path=config_path,output_file=args.output) 
        logger.debug("扫描引擎配置加载完成。")

        if hasattr(engine, 'reporter') and engine.reporter:
             reporter = engine.reporter 
             logger.info("从引擎获取 ConsoleReporter 实例。")

        if reporter:
            reporter.report_start(total_targets=len(targets))
        else:
            logger.error("Reporter 未初始化，无法记录任务开始信息。")

        
        browser_config = engine.config.get('browser', {})
        max_concurrency = browser_config.get('max_concurrency', 4)
        if not isinstance(max_concurrency, int) or max_concurrency <= 0:
             logger.warning(f"配置中的并发数 '{max_concurrency}' 无效，将使用默认值 1。")
             max_concurrency = 1
        logger.info(f"设置最大并发 Worker 数: {max_concurrency}")

        
        browser_manager = BrowserManager()
        logger.info("BrowserManager 初始化完成。")

        
        browser_config = engine.config.get('browser', {}) 
        headless_mode = browser_config.get('headless', False)
        browser_type = browser_config.get('type', 'chromium')
        launch_options = _prepare_launch_options(browser_config, logger) 
        logger.info(f"正在启动共享浏览器 (类型: {browser_type}, 无头: {headless_mode})...")
        
        shared_browser = await browser_manager.launch_browser(
            headless=headless_mode,
            browser_type=browser_type,
            **launch_options
        )
        if not shared_browser:
            logger.critical("无法启动共享浏览器实例。程序无法继续。")
            return 
        browser_launched = True
        logger.info("共享浏览器实例启动成功。")

        
        context_options = _prepare_context_options(browser_config, logger) 
        logger.info(f"正在创建 {max_concurrency} 个持久化浏览器上下文...")
        for i in range(max_concurrency):
            try:
                context = await browser_manager.create_new_context(options=context_options)
                if context:
                    persistent_contexts.append(context)
                    logger.debug(f"成功创建第 {i+1}/{max_concurrency} 个浏览器上下文。")
                else:
                    logger.error(f"创建第 {i+1}/{max_concurrency} 个浏览器上下文失败。")
                    
            except Exception as ctx_err:
                logger.error(f"创建第 {i+1}/{max_concurrency} 个浏览器上下文时发生异常: {ctx_err}", exc_info=True)

        if not persistent_contexts:
            logger.critical("未能成功创建任何浏览器上下文。程序无法继续。")
            return
        logger.info(f"成功创建 {len(persistent_contexts)} 个持久化浏览器上下文。")
        
        actual_concurrency = len(persistent_contexts)
        logger.info(f"实际可用 Worker 数: {actual_concurrency}")

        
        task_queue = asyncio.Queue()
        for url in targets:
            await task_queue.put(url)
        
        for _ in range(actual_concurrency):
            await task_queue.put(None)

        logger.info(f"开始启动 {actual_concurrency} 个 Worker 协程...")
        worker_tasks = []
        for i in range(actual_concurrency):
            task = asyncio.create_task(worker(i + 1, persistent_contexts[i], engine, browser_manager, task_queue))
            worker_tasks.append(task)

        
        logger.info("所有 Worker 已启动，等待任务队列处理完成...")
        
        await task_queue.join()
        logger.info("任务队列已处理完毕。")

        
        worker_results = await asyncio.gather(*worker_tasks, return_exceptions=True)

        logger.info("所有 Worker 协程已结束。")

        for i, res in enumerate(worker_results):
            if isinstance(res, Exception) and not isinstance(res, asyncio.CancelledError):
                logger.error(f"Worker {i+1} 最终返回了一个未处理的异常: {res}", exc_info=isinstance(res, BaseException))

    except FileNotFoundError as e:
        logger.error(f"引擎初始化失败：{e}")
    except Exception as e:
        logger.critical(f"在主流程设置阶段发生严重错误: {e}", exc_info=True)
    finally:
        
        logger.info("开始清理资源...")

        
        if reporter and reporter.start_time: 
            try:
                reporter.report_end()
            except Exception as report_end_err:
                logger.error(f"记录任务结束报告时发生错误: {report_end_err}", exc_info=True)

        
        if persistent_contexts:
            logger.info(f"正在关闭 {len(persistent_contexts)} 个浏览器上下文...")
            context_close_tasks = [ctx.close() for ctx in persistent_contexts]
            
            results = await asyncio.gather(*context_close_tasks, return_exceptions=True)
            for i, res in enumerate(results):
                if isinstance(res, Exception):
                    logger.warning(f"关闭上下文 {i+1} 时发生错误: {res}")
            logger.info("所有浏览器上下文已尝试关闭。")

        if browser_manager and browser_launched: 
            logger.info("正在关闭共享浏览器实例...")
            try:
                await browser_manager.close_browser()
                logger.info("共享浏览器实例已关闭。")
            except Exception as browser_close_err:
                logger.error(f"关闭共享浏览器时发生错误: {browser_close_err}", exc_info=True)

        if browser_manager:
            logger.info("正在关闭 Playwright...")
            try:
                await browser_manager.shutdown_playwright()
                logger.info("Playwright 已关闭。")
            except Exception as pw_shutdown_err:
                 logger.error(f"关闭 Playwright 时发生错误: {pw_shutdown_err}", exc_info=True)

    logger.info("AuthScope 应用程序正常退出。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n检测到用户中断 (Ctrl+C)，程序即将退出。")
        logging.getLogger(__name__).warning("用户请求中断。")
    except Exception as top_level_error:
        logging.getLogger(__name__).critical(f"应用程序顶层发生致命错误: {top_level_error}", exc_info=True)
        sys.exit(1)