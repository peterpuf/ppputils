import datetime
import builtins

original_print = builtins.print


def set_print_with_prefix(prefix):
    """
    重定义print函数, 加入日期时间打印及自定义前缀内容
    使用方式:
        set_print_with_prefix("prefix")
        print("123123")
    :return:
    """

    def new_print(*args, **kwargs):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        original_print(f"[{current_time}] | {prefix} |", *args, **kwargs)

    builtins.print = new_print


def print(*args, **kwargs):
    """
    重定义print函数, 加入日期时间打印
    使用方式:
        from formats import print
        print("123123")
    :return:
    """
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    original_print(f"[{current_time}]", *args, **kwargs)
