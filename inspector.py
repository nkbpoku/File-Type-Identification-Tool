from pathlib import Path


def looks_like_text(data):
    if not data:
        return False

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    return all(
        character.isprintable() or character in "\n\r\t"
        for character in text
    )


def inspect_file(file_path):
    path = Path(file_path)
    extension = path.suffix.lower()

    with path.open("rb") as file:
        file_info = path.stat()
        sample = file.read(4096)

    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_format = "PNG image"
        suggested_extension = ".png"
        comparison = (
            "Extension matches the signature"
            if extension == ".png"
            else "Extension mismatch"
        )
        evidence = "PNG signature found at the start of the file."

    elif sample.startswith(b"%PDF-"):
        detected_format = "PDF document"
        suggested_extension = ".pdf"
        comparison = (
            "Extension matches the signature"
            if extension == ".pdf"
            else "Extension mismatch"
        )
        evidence = "PDF header signature %PDF- found at the start."

    elif file_info.st_size <= 4096 and looks_like_text(sample):
        detected_format = "Plain text candidate"
        suggested_extension = ".txt (tentative)"
        comparison = "Inconclusive — text alone does not establish a format"
        evidence = (
            "The entire file decodes as UTF-8 and contains only "
            "printable characters or ordinary whitespace."
        )

    else:
        detected_format = "Unknown"
        suggested_extension = "Unable to determine"
        comparison = "Inconclusive"
        evidence = (
            "No supported signature matched. The basic text check "
            "covers only non-empty UTF-8 files up to 4,096 bytes."
        )

    return {
        "name": path.name,
        "location": str(path.resolve()),
        "extension": extension or "No extension",
        "size_bytes": file_info.st_size,
        "detected_format": detected_format,
        "suggested_extension": suggested_extension,
        "comparison": comparison,
        "original_name": "Unknown — no rename history available",
        "evidence": evidence,
    }