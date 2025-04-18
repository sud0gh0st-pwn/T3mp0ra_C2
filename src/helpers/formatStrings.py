
class bcolors:
    """
    Enhanced ANSI escape code class for terminal text styling.
    
    Usage:
        print(f"{bcolors.RED}Error: {bcolors.RESET}Something went wrong!")
        print(bcolors.style(bcolors.BG_BLUE, bcolors.BOLD, bcolors.LIGHT_YELLOW) + "Styled text" + bcolors.RESET)
    """
    # Text colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Light text colors
    LIGHT_BLACK = '\033[90m'
    LIGHT_RED = '\033[91m'
    LIGHT_GREEN = '\033[92m'
    LIGHT_YELLOW = '\033[93m'
    LIGHT_BLUE = '\033[94m'
    LIGHT_MAGENTA = '\033[95m'
    LIGHT_CYAN = '\033[96m'
    LIGHT_WHITE = '\033[97m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Light background colors
    BG_LIGHT_BLACK = '\033[100m'
    BG_LIGHT_RED = '\033[101m'
    BG_LIGHT_GREEN = '\033[102m'
    BG_LIGHT_YELLOW = '\033[103m'
    BG_LIGHT_BLUE = '\033[104m'
    BG_LIGHT_MAGENTA = '\033[105m'
    BG_LIGHT_CYAN = '\033[106m'
    BG_LIGHT_WHITE = '\033[107m'

        # Styles
    RESET = '\033[0m'      # Alias for ENDC
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    INVERT = '\033[7m'
    HIDDEN = '\033[8m'
    STRIKE = '\033[9m'

    @staticmethod
    def style(*styles: str) -> str:
        codes = []
        for style in styles:
            code = style.replace('\033[', '').replace('m', '')
            if ';' in code:
                codes.extend(code.split(';'))
            else:
                codes.append(code)
        return f'\033[{";".join(codes)}m'

    # Now define common combinations AFTER the style method exists
    WARNING = style(BOLD, YELLOW)
    FAIL = style(BOLD, RED)
    HEADER = style(BOLD, UNDERLINE, LIGHT_MAGENTA)
    SUCCESS = style(BOLD, GREEN)
    INFO = style(BOLD, BLUE)

    @staticmethod
    def style(*styles: str) -> str:
        """
        Combine multiple styles into a single escape sequence
        
        Args:
            *styles: Any number of style constants from the class
            
        Returns:
            Combined ANSI escape code string
            
        Example:
            print(bcolors.style(bcolors.BG_BLUE, bcolors.BOLD, bcolors.LIGHT_YELLOW) + "Text" + bcolors.RESET)
        """
        codes = []
        for style in styles:
            code = style.replace('\033[', '').replace('m', '')
            if ';' in code:
                codes.extend(code.split(';'))
            else:
                codes.append(code)
        return f'\033[{";".join(codes)}m'

    @staticmethod
    def rgb(r: int, g: int, b: int, background: bool = False) -> str:
        """
        Generate RGB color code (requires terminal support)
        
        Args:
            r: Red value (0-255)
            g: Green value (0-255)
            b: Blue value (0-255)
            background: True for background color
            
        Returns:
            ANSI escape code for RGB color
        """
        type_ = '48' if background else '38'
        return f'\033[{type_};2;{r};{g};{b}m'

    class Context:
        """Context manager for automatic style resetting"""
        def __init__(self, *styles: str):
            self.styles = styles
            
        def __enter__(self):
            print(bcolors.style(*self.styles), end='')
            
        def __exit__(self, exc_type, exc_value, traceback):
            print(bcolors.RESET, end='')

# Aliases for common usage
RESET = bcolors.RESET
R = bcolors.RESET