"""Greeting banners."""
from string import Template


class User:
    def __init__(self, name: str):
        self.name = name


def banner(template: str, name: str) -> str:
    return Template(template).safe_substitute(name=User(name).name)
