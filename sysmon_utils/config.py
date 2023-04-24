from dataclasses import dataclass

from rich.console import Console


@dataclass
class Config:
    console: Console
    debug: bool = False


config = Config(console=Console())
