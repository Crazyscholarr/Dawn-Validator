from colorama import Fore


def error_log(message: str):
    print(Fore.RED + ">> Crazyscholar |" + Fore.LIGHTBLACK_EX + f" {message}")


def success_log(message: str):
    print(Fore.GREEN + ">> Crazyscholar |" + Fore.LIGHTBLACK_EX + f" {message}")


def info_log(message: str):
    print(Fore.LIGHTBLACK_EX + f">> Crazyscholar | {message}")
