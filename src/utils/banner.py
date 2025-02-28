import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from datetime import datetime

class Banner:
    def __init__(self):
        self.console = Console()

    def show_banner(self):
        """Display the tool banner with styling"""
        banner_text = """
 ███████╗ ██████╗ ██████╗  ██████╗ 
 ╚══███╔╝██╔═══██╗██╔══██╗██╔═══██╗
   ███╔╝ ██║   ██║██████╔╝██║   ██║
  ███╔╝  ██║   ██║██╔══██╗██║   ██║
 ███████╗╚██████╔╝██║  ██║╚██████╔╝
 ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
        """

        subtitle = "Domain Reconnaissance Toolkit"
        version = "v1.0.0"

        # Create styled banner
        banner = Text(banner_text, style="bold cyan")
        banner.append("\n" + subtitle + "\n", style="italic yellow")
        banner.append(version + "\n", style="dim blue")

        # Add timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        banner.append(f"\nStarted at: {timestamp}", style="dim")

        # Display in a panel
        self.console.print(Panel(banner, border_style="cyan"))

    def create_progress(self):
        """Create a rich progress bar for tracking operations"""
        return Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description:<30}"),
            BarColumn(complete_style="green", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        )

    def show_summary_table(self, results):
        """Display results in a formatted table"""
        table = Table(
            title="Reconnaissance Summary",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan",
            title_style="bold cyan"
        )

        table.add_column("Category", style="cyan", justify="right")
        table.add_column("Details", style="green")

        for key, value in results.items():
            # Format certain values
            if isinstance(value, float):
                formatted_value = f"{value:.2f}"
            elif isinstance(value, (int, str)):
                formatted_value = str(value)
            else:
                formatted_value = repr(value)

            table.add_row(key, formatted_value)

        self.console.print("\n")
        self.console.print(table)
        self.console.print("\n")

    def task_header(self, title):
        """Display a section header with improved styling"""
        self.console.print("\n")
        self.console.print("┌" + "─" * 48 + "┐", style="cyan")
        self.console.print("│" + title.center(48) + "│", style="bold white")
        self.console.print("└" + "─" * 48 + "┘", style="cyan")
        self.console.print("\n")