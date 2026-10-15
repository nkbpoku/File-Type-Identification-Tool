from pathlib import Path
from zipfile import ZipFile, BadZipFile


# Conservative limits for this first version.
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 2000


def inspect_office_container(file_path):
    path = Path(file_path)

    result = {
        "description": None,
        "extensions": (),
        "findings": [],
        "evidence": "",
    }

    # Check the outer header before asking the ZIP parser to read it.
    with path.open("rb") as file:
        signature = file.read(4)

    if signature not in (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
    ):
        return result

    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        result["findings"].append(
            "Office container check skipped: this ZIP-based file "
            "exceeds the current 8 MB inspection limit."
        )
        return result

    try:
        with ZipFile(path, "r") as archive:
            entries = archive.infolist()

            if len(entries) > MAX_ENTRIES:
                result["findings"].append(
                    "Office container check stopped: the archive "
                    "contains more than 2,000 entries."
                )
                return result

            names = {
                entry.filename
                for entry in entries
                if not entry.is_dir()
            }

            if len(names) != sum(
                not entry.is_dir() for entry in entries
            ):
                result["findings"].append(
                    "The archive lists duplicate filenames. "
                    "Different programs may interpret these differently."
                )

            if any(entry.flag_bits & 1 for entry in entries):
                result["findings"].append(
                    "Some archive entries are encrypted. "
                    "Their contents were not inspected."
                )

    except (BadZipFile, ValueError, NotImplementedError):
        result["findings"].append(
            "The file starts like a ZIP archive, but its "
            "directory could not be read."
        )
        return result

    # A named macro project is an indicator, not proof of its behaviour.
    macro_paths = sorted(
        name for name in names
        if name.rsplit("/", 1)[-1].lower() == "vbaproject.bin"
    )

    if macro_paths:
        result["findings"].append(
            "An entry named vbaProject.bin was found. "
            "This suggests an embedded VBA macro project. "
            "Its code and behaviour were not analysed."
        )

    required_package_entries = {
        "[Content_Types].xml",
        "_rels/.rels",
    }

    families = [
        (
            "word/document.xml",
            "Word document",
            (".docx", ".docm", ".dotx", ".dotm"),
            (".docm", ".dotm"),
        ),
        (
            "xl/workbook.xml",
            "Excel spreadsheet",
            (".xlsx", ".xlsm", ".xltx", ".xltm"),
            (".xlsm", ".xltm"),
        ),
        (
            "ppt/presentation.xml",
            "PowerPoint presentation",
            (
                ".pptx", ".pptm", ".potx",
                ".potm", ".ppsx", ".ppsm",
            ),
            (".pptm", ".potm", ".ppsm"),
        ),
    ]

    matches = [
        family for family in families
        if family[0] in names
    ]

    result["evidence"] = (
        f"Read the ZIP directory: {len(entries)} entries.\n"
        "No entries were extracted or decompressed.\n"
    )

    if len(matches) > 1:
        result["findings"].append(
            "The archive contains markers for several Office formats. "
            "Its document type is ambiguous."
        )
        return result

    if not matches:
        result["evidence"] += (
            "No supported Office document markers were found."
        )
        return result

    if not required_package_entries.issubset(names):
        result["findings"].append(
            "An Office document marker was found, but expected "
            "package entries are missing. The format is unconfirmed."
        )
        return result

    marker, label, extensions, macro_extensions = matches[0]

    result["description"] = f"{label} candidate (ZIP-based)"
    result["extensions"] = (
        macro_extensions if macro_paths else extensions
    )
    result["evidence"] += (
        f"Found {marker}, [Content_Types].xml and _rels/.rels.\n"
        "Classification is based on entry names only. XML content, "
        "relationships and document validity were not checked. "
        "The exact Office subtype remains unconfirmed."
    )

    return result