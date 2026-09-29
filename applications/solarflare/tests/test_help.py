"""Every command is documented: a help entry with examples, and help text on every option."""
import argparse
import contextlib
import io
import unittest
from pathlib import Path

from solarflare import cli, helptext
from solarflare.cloudflare.api import TOKEN_PERMISSIONS


class Help(unittest.TestCase):
    def setUp(self):
        _, self.commands = cli.build_parser()

    def test_every_command_is_in_the_help(self):
        commands = set(self.commands) - {"help"}
        self.assertEqual(commands - set(helptext.GUIDE), set())
        for name in commands:
            self.assertTrue(helptext.GUIDE[name]["examples"] or helptext.GUIDE[name].get("ways"), name)

    def test_every_option_has_help_text(self):
        for name, parser in self.commands.items():
            for action in parser._actions:
                if not isinstance(action, argparse._HelpAction):
                    self.assertTrue(action.help, f"{name}: {action.dest} has no help text")

    def test_overview_lists_the_tools(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["help"])
        for name in ("sample", "summary", "usage", "security", "investigate", "collect"):
            self.assertIn(name, out.getvalue())

    def test_readme_lists_the_same_token_permissions(self):
        readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
        for scope, permission, _ in TOKEN_PERMISSIONS:
            self.assertIn(f"| {scope} | {permission} |", readme)


if __name__ == "__main__":
    unittest.main()
