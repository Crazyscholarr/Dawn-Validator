import os
import sys
import inquirer

from inquirer.themes import GreenPassion
from art import text2art
from colorama import Fore
from loader import config

from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

sys.path.append(os.path.realpath("."))


class Console:
    MODULES = (
        "Tạo tài khoản",
        "Canh tác tài khoản",
        "Làm tasks",
        "Xác minh lại tài khoản",
        "Thống kê tài khoản",
        "Exit",
    )
    MODULES_DATA = {
        "Tạo tài khoản": "register",
        "Canh tác tài khoản": "farm",
        "Exit": "exit",
        "Thống kê tài khoản": "export_stats",
        "Làm tasks": "complete_tasks",
        "Xác minh lại tài khoản": "re_verify_accounts",
    }

    def __init__(self):
        self.rich_console = RichConsole()

    def show_dev_info(self):
        os.system("cls" if os.name == "nt" else "clear")

        title = text2art("DAWN Validator", font="ANSI Shadow")
        styled_title = Text(title, style="bold cyan")

        version = Text("VERSION: 1.8", style="blue")
        telegram = Text("Channel: https://t.me/crazyscholarr", style="magenta")
        

        dev_panel = Panel(
            Text.assemble(styled_title, "\n", version, "\n", telegram, "\n"),
            border_style="yellow",
            expand=False,
            title="[bold green]Welcome[/bold green]",
            subtitle="[italic]Powered by Crazyscholar[/italic]",
        )

        self.rich_console.print(dev_panel)
        print()

    @staticmethod
    def prompt(data: list):
        answers = inquirer.prompt(data, theme=GreenPassion())
        return answers

    def get_module(self):
        questions = [
            inquirer.List(
                "module",
                message=Fore.LIGHTBLACK_EX + "Chọn mô-đun để chạy:",
                choices=self.MODULES,
            ),
        ]

        answers = self.prompt(questions)
        return answers.get("module")

    def display_info(self):
        table = Table(title="Dawn Configuration", box=box.ROUNDED)
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="magenta")

        if config.redirect_settings.enabled:
            table.add_row("Redirect mode", "Enabled")
            table.add_row("Redirect email", config.redirect_settings.email)

        table.add_row("Tài khoản để đăng ký", str(len(config.accounts_to_register)))
        table.add_row("Tài khoản để canh tác", str(len(config.accounts_to_farm)))
        table.add_row("Tài khoản cần xác minh lại", str(len(config.accounts_to_reverify)))
        table.add_row("Threads", str(config.threads))
        table.add_row(
            "Trì hoãn trước khi bắt đầu",
            f"{config.delay_before_start.min} - {config.delay_before_start.max} sec",
        )

        panel = Panel(
            table,
            expand=False,
            border_style="green",
            title="[bold yellow]Thông tin hệ thống[/bold yellow]",
            subtitle="[italic]Sử dụng các phím mũi tên để điều hướng[/italic]",
        )
        self.rich_console.print(panel)

    def build(self) -> None:
        self.show_dev_info()
        self.display_info()

        module = self.get_module()
        config.module = self.MODULES_DATA[module]

        if config.module == "exit":
            exit(0)
