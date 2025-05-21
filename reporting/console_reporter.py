
import logging
import os
import datetime 
from typing import Optional

class ConsoleReporter:
    """
    负责将扫描结果格式化并输出到控制台和文件的报告器。
    增加全局任务信息报告功能（开始、结束、耗时）。
    """
    def __init__(self, output_dir: str = "results", filename: str = "scan_report.txt"):
        """
        初始化报告器。

        Args:
            output_dir (str): 用于存储报告文件的目录路径。默认为 "results"。
            filename (str): 报告文件的名称。默认为 "scan_report.txt"。
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir
        self.output_file_path = os.path.join(self.output_dir, filename)
        self.start_time: Optional[datetime.datetime] = None 
        self.total_targets: int = 0 

        
        try:
            os.makedirs(self.output_dir, exist_ok=True) 
            self.logger.info(f"报告输出位置为: {self.output_file_path}")
        except OSError as e:
            self.logger.error(f"创建报告输出目录 '{self.output_dir}' 失败: {e}。将无法写入报告文件。")
            self.output_file_path = None 

    def report_start(self, total_targets: int):
        """
        记录任务开始时间，报告总目标数，并写入报告文件头。
        """
        self.start_time = datetime.datetime.now()
        self.total_targets = total_targets
        start_time_str = self.start_time.strftime('%Y-%m-%d %H:%M:%S')

        header_lines = [
            "=" * 70,
            f"AuthScope 扫描任务开始",
            f"开始时间: {start_time_str}",
            f"目标总数: {self.total_targets}",
            "=" * 70,
            "\n" 
        ]
        header_content = "\n".join(header_lines)

        
        print(header_content.strip())
        self.logger.info(f"扫描任务开始，共 {self.total_targets} 个目标。")

        
        self.logger.info(f"正在初始化报告文件: {self.output_file_path}")
        self._write_to_file(header_content, mode='a')

    def report_end(self):
        """
        记录任务结束时间，计算总耗时，并追加写入报告文件尾部。
        """
        if not self.start_time:
            self.logger.warning("无法记录结束报告，因为开始时间未被记录。")
            return

        end_time = datetime.datetime.now()
        duration = end_time - self.start_time
        end_time_str = end_time.strftime('%Y-%m-%d %H:%M:%S')

        
        total_seconds = duration.total_seconds()
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{int(hours)} 小时 {int(minutes)} 分钟 {seconds:.2f} 秒"

        footer_lines = [
            "\n", 
            "=" * 70,
            f"AuthScope 扫描任务结束",
            f"结束时间: {end_time_str}",
            f"总耗时:   {duration_str}",
            "=" * 70,
            "\n"
        ]
        footer_content = "\n".join(footer_lines)

        
        print(footer_content.strip())
        self.logger.info(f"扫描任务结束，总耗时: {duration_str}。")

        
        self.logger.info("正在将任务总结写入报告文件...")
        self._write_to_file(footer_content, mode='a')

    def _format_report(self, url: str, analysis_result: dict | None = None, error: str | None = None, found_weak_password: bool | None = None, successful_credential: tuple | None = None, attempts_summary: list | None = None) -> str:
        """
        将单个目标的扫描结果格式化为易于阅读的字符串。

        Args:
            url (str): 目标 URL。
            analysis_result (dict | None): 来自 Engine 的分析结果摘要 (键: 元素名称, 值: "存在"/"未找到")。
            error (str | None): 扫描过程中发生的顶层错误信息。
            found_weak_password (bool | None): 是否找到弱口令。
            successful_credential (tuple | None): 找到的弱口令凭证 (username, password)。
            attempts_summary (list | None): 登录尝试的详细列表，每个元素是一个包含 'credential', 'status', 'operation_error', 'detection_error' 的字典。

        Returns:
            str: 格式化后的报告文本。
        """
        lines = []
        lines.append("=" * 70)
        lines.append(f"[*] 扫描目标: {url}")
        lines.append(f"[*] 报告时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("-" * 70)

        
        if error:
            lines.append("[!] 扫描中止或遇到严重错误:")
            lines.append(f"    详细信息: {error}")
            lines.append("=" * 70)
            return "\n".join(lines) + "\n\n" 

        
        if not found_weak_password:
            lines.append("[+] 登录界面分析结果 (因未找到弱口令而展示):")
            if analysis_result:
                username_status = analysis_result.get('username_locator', '未分析')
                password_status = analysis_result.get('password_locator', '未分析')
                submit_status = analysis_result.get('submit_locator', '未分析')

                lines.append(f"    用户名输入框: {username_status}" + (" [!] 未找到或分析失败" if username_status == '未分析' else ""))
                lines.append(f"    密码输入框:   {password_status}" + (" [!] 未找到或分析失败" if password_status == '未分析' else ""))
                lines.append(f"    提交按钮:     {submit_status}" + (" [!] 未找到或分析失败" if submit_status == '未分析' else ""))

                
                captcha_image_status = analysis_result.get('captcha_image_locator', '未分析或未找到')
                captcha_input_status = analysis_result.get('captcha_input_locator', '未分析或未找到')

                image_found = captcha_image_status != '未分析或未找到'
                input_found = captcha_input_status != '未分析或未找到'

                
                if image_found and input_found:
                    lines.append(f"    验证码图片:   {captcha_image_status}")
                    lines.append(f"    验证码输入框: {captcha_input_status}")
                elif not image_found and not input_found:
                    lines.append("    验证码相关组件: 未找到 (或无需验证码)")
                elif image_found and not input_found:
                    
                    lines.append(f"    验证码图片:   {captcha_image_status}")
                    lines.append(f"    验证码输入框: {'未分析或未找到'} [!] 异常：仅找到图片")
                elif not image_found and input_found:
                    
                    lines.append(f"    验证码图片:   {'未分析或未找到'} [!] 异常：仅找到输入框")
                    lines.append(f"    验证码输入框: {captcha_input_status}")

            else:
                lines.append("    未能获取有效的分析结果 (可能分析失败或未找到元素)。")

            lines.append("-" * 70)

        
        lines.append("[+] 弱口令检测结果:")
        if found_weak_password is None and attempts_summary is None:
             
             lines.append("    由于分析阶段问题或缺少凭证，未执行登录尝试。")
        elif found_weak_password:
             lines.append("    [!!!] 发现弱口令!")
             lines.append(f"        凭证: 用户名='{successful_credential[0]}', 密码='{successful_credential[1]}'")
        else:
             lines.append("    未发现弱口令。")

        lines.append("-" * 70)

        
        lines.append("[+] 登录尝试详情:")
        if attempts_summary:
            total_attempts = len(attempts_summary)
            lines.append(f"    总尝试次数: {total_attempts}")
            
            if total_attempts > 0:
                lines.append("    部分尝试记录:") 
                count = 0
                for i, attempt in enumerate(attempts_summary):
                    user, pwd = attempt['credential']
                    status = attempt['status']
                    op_error = attempt.get('operation_error') 
                    det_error = attempt.get('detection_error') 

                    
                    
                    line = f"      {i+1}. 用户名: '{user}', 密码: '{pwd}' -> 结果: {status}"
                    if op_error:
                        line += f" (操作错误: {op_error})"
                    if det_error:
                         line += f" (检测错误: {det_error})" 
                    lines.append(line)
                    count += 1

            else: 
                 lines.append("    没有进行任何尝试。")
        elif found_weak_password is not None: 
             lines.append("    执行了登录尝试，但详情记录丢失。")
        

        lines.append("=" * 70)
        return "\n".join(lines) + "\n\n" 

    def _write_to_file(self, content: str, mode: str = 'a'):
        """
        将内容写入报告文件。

        Args:
            content (str): 要写入文件的报告内容。
            mode (str): 文件打开模式 ('w' for write, 'a' for append)。默认为 'a'。
        """
        if not self.output_file_path:
            self.logger.warning("输出文件路径无效，无法写入报告文件。")
            return

        try:
            
            with open(self.output_file_path, mode, encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            self.logger.error(f"无法以模式 '{mode}' 写入报告文件 {self.output_file_path}: {e}", exc_info=True)
        except Exception as e:
            self.logger.error(f"以模式 '{mode}' 写入报告文件时发生意外错误: {e}", exc_info=True)

    def report(self, url: str, analysis_result: dict | None = None, error: str | None = None, found_weak_password: bool | None = None, successful_credential: tuple | None = None, attempts_summary: list | None = None):
        """
        生成报告，输出到控制台并追加写入文件。

        Args:
            url (str): 目标 URL。
            analysis_result (dict | None): 来自 Engine 的分析结果摘要。
            error (str | None): 顶层错误信息。
            found_weak_password (bool | None): 是否找到弱口令。
            successful_credential (tuple | None): 找到的弱口令凭证。
            attempts_summary (list | None): 登录尝试的详细列表。
        """
        
        try:
             report_content = self._format_report(
                 url=url,
                 analysis_result=analysis_result,
                 error=error,
                 found_weak_password=found_weak_password,
                 successful_credential=successful_credential,
                 attempts_summary=attempts_summary
             )
        except Exception as format_err:
             self.logger.error(f"格式化报告内容时出错 for URL {url}: {format_err}", exc_info=True)
             
             report_content = f"[*] Target: {url}\n[!] Failed to format report: {format_err}\n\n"

        
        
        print(report_content.strip())

        
        self._write_to_file(report_content, mode='a') 