def get_choice(max_option: int):
    from rich.prompt import Prompt

    choices = [str(x) for x in range(max_option + 1)]
    return Prompt.ask("[maroon]Enter your choice:[/maroon]", choices = choices)