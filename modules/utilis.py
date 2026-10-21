"""
Collection of utility functions for various purposes.

Functions:
-  display_severity(): Display an icon based on the severity value.
"""


SEVERITY_ICON = {0: "✅", 10: "🔵", 20: "🟠", 30: "❌"}

# Coloured words, for anything rendered inside a rich Table. The emoji above are
# double-width in most terminals but rich measures some of them as one cell, so a
# column holding them ends up narrower than it renders and every border below it
# shifts. Markup tags are excluded from rich's width calculation, so these align.
SEVERITY_WORD = {0: "OK", 10: "INFO", 20: "WARN", 30: "BLOCK"}
_SEVERITY_COLOUR = {0: "green", 10: "blue", 20: "yellow", 30: "red"}
SEVERITY_TEXT = {
    level: f"[{_SEVERITY_COLOUR[level]}]{word}[/{_SEVERITY_COLOUR[level]}]"
    for level, word in SEVERITY_WORD.items()
}


def display_severity(value: int, text: bool = False):
    """
    Display the corresponding icon based on the severity value.

    Parameters:
    - value (int): The severity value (SeverityInfo.severity).
    - text (bool): Return the coloured word instead of the emoji. Use this for
      anything rendered inside a rich Table (see SEVERITY_TEXT).

    Returns:
    - str: 0 green, 10 blue, 20 amber, 30 red, anything else unknown.
    """
    if text:
        return SEVERITY_TEXT.get(value, "[dim]?[/dim]")
    return SEVERITY_ICON.get(value, "❓")
