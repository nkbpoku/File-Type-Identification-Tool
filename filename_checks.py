from pathlib import Path
import unicodedata


# Extensions that commonly look like ordinary documents or media.
DOCUMENT_EXTENSIONS = {
    ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif",
}

# These formats can contain programs, commands or shortcuts.
ACTIVE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".msi", ".lnk",
    ".sh", ".app",
}

# Characters that can change the displayed direction of a filename.
DIRECTION_CHARACTERS = {
    "\u061c", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}


def check_filename(file_path):
    name = Path(file_path).name
    extensions = [
        extension.lower()
        for extension in Path(name).suffixes
    ]

    findings = []

    if len(extensions) >= 2:
        final_extension = extensions[-1]
        earlier_extensions = extensions[:-1]

        if (
            final_extension in ACTIVE_EXTENSIONS
            and any(
                extension in DOCUMENT_EXTENSIONS
                for extension in earlier_extensions
            )
        ):
            findings.append({
                "level": "Warning",
                "message": (
                    f"The name contains a document or image extension, "
                    f"but ends in {final_extension}. "
                    "This can make a program or shortcut look like "
                    "an ordinary document."
                ),
            })
        else:
            findings.append({
                "level": "Info",
                "message": (
                    "The filename has multiple extensions. "
                    "This can be normal, such as an archive named "
                    "backup.tar.gz."
                ),
            })

    direction_codes = sorted({
        f"U+{ord(character):04X}"
        for character in name
        if character in DIRECTION_CHARACTERS
    })

    if direction_codes:
        findings.append({
            "level": "Warning",
            "message": (
                "The filename contains text-direction characters "
                f"({', '.join(direction_codes)}). "
                "The extension may appear differently on screen "
                "from its actual order."
            ),
        })

    hidden_codes = sorted({
        f"U+{ord(character):04X}"
        for character in name
        if (
            unicodedata.category(character) in {"Cc", "Cf"}
            and character not in DIRECTION_CHARACTERS
        )
    })

    if hidden_codes:
        findings.append({
            "level": "Notice",
            "message": (
                "The filename contains control or formatting "
                f"characters ({', '.join(hidden_codes)}). "
                "Some may be invisible or affect how the name displays."
            ),
        })

    if name.endswith((" ", ".")):
        findings.append({
            "level": "Notice",
            "message": (
                "The filename ends with a space or dot. "
                "Some systems handle these names differently."
            ),
        })

    return findings