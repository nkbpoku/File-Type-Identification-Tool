from pathlib import Path
from zipfile import ZipFile, BadZipFile

from outcomes import check_result


MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 2000


def inspect_office_container(file_path):
    """Inspect ZIP entry names only; do not extract or decompress payloads."""
    path = Path(file_path)
    result = {
        "description": None,
        "extensions": (),
        "checks": [],
        "evidence": "",
    }
    checks = result["checks"]

    with path.open("rb") as file:
        signature = file.read(4)

    if signature not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        checks.append(check_result(
            "not_applicable", "OFFICE_NOT_APPLICABLE",
            "No supported ZIP header at byte 0; this Office ZIP check does not apply. "
            "Other containers and embedded ZIP data were not searched.",
        ))
        return result

    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        checks.append(check_result(
            "incomplete", "OFFICE_SIZE_LIMIT",
            "Office container check skipped: this ZIP-based file exceeds "
            "the current 8 MiB inspection limit. This alone is not suspicious.",
        ))
        return result

    try:
        with ZipFile(path, "r") as archive:
            # ZipFile loads its directory before this entry-count check.
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                checks.append(check_result(
                    "incomplete", "OFFICE_ENTRY_LIMIT",
                    "Office container check stopped: more than 2,000 entries. "
                    "This alone is not suspicious.",
                ))
                return result

            file_entries = [entry for entry in entries if not entry.is_dir()]
            names = {entry.filename for entry in file_entries}
            if len(names) != len(file_entries):
                checks.append(check_result(
                    "finding", "ZIP_DUPLICATE_NAMES",
                    "The archive lists duplicate filenames. Programs may "
                    "interpret these differently; review is recommended.",
                ))

            if any(entry.flag_bits & 1 for entry in entries):
                checks.append(check_result(
                    "incomplete", "ZIP_ENCRYPTED_ENTRIES",
                    "Some archive entries are marked encrypted. Their contents "
                    "were not inspected. Encryption alone is not malicious.",
                ))

    except (BadZipFile, ValueError, NotImplementedError, OSError):
        checks.append(check_result(
            "incomplete", "ZIP_DIRECTORY_UNREADABLE",
            "The file starts like a ZIP archive, but its directory could not "
            "be read. Its contents remain unconfirmed.",
        ))
        return result

    macro_paths = sorted(
        name for name in names
        if name.rsplit("/", 1)[-1].lower() == "vbaproject.bin"
    )
    if macro_paths:
        checks.append(check_result(
            "finding", "OFFICE_VBA_INDICATOR",
            "An entry named vbaProject.bin was found. This suggests an "
            "embedded VBA macro project. Its code and behaviour were not "
            "analysed; legitimate documents can contain macros.",
        ))

    families = [
        ("word/document.xml", "Word document",
         (".docx", ".docm", ".dotx", ".dotm"), (".docm", ".dotm")),
        ("xl/workbook.xml", "Excel spreadsheet",
         (".xlsx", ".xlsm", ".xltx", ".xltm"), (".xlsm", ".xltm")),
        ("ppt/presentation.xml", "PowerPoint presentation",
         (".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"),
         (".pptm", ".potm", ".ppsm")),
    ]
    matches = [family for family in families if family[0] in names]
    result["evidence"] = (
        f"Read the ZIP directory: {len(entries)} entries.\n"
        "No entries were extracted or decompressed.\n"
    )

    if len(matches) > 1:
        checks.append(check_result(
            "incomplete", "OFFICE_AMBIGUOUS_TYPE",
            "Markers for several Office formats were found. The document "
            "type remains ambiguous.",
        ))
        return result

    if not matches:
        checks.append(check_result(
            "not_applicable", "OFFICE_NO_SUPPORTED_MARKERS",
            "No supported Office main-document entry names were found. "
            "This does not exclude other document formats or active content.",
        ))
        return result

    if not {"[Content_Types].xml", "_rels/.rels"}.issubset(names):
        checks.append(check_result(
            "incomplete", "OFFICE_PACKAGE_INCOMPLETE",
            "An Office marker was found, but expected package entries are "
            "missing. The format is unconfirmed.",
        ))
        return result

    marker, label, extensions, macro_extensions = matches[0]
    result["description"] = f"{label} candidate (ZIP-based)"
    result["extensions"] = macro_extensions if macro_paths else extensions
    checks.append(check_result(
        "consistent", "OFFICE_MARKERS_CONSISTENT",
        f"Entry names are consistent with a {label.lower()} candidate. "
        "XML contents, relationships, exact subtype and document validity "
        "were not checked.",
    ))
    result["evidence"] += (
        f"Found {marker}, [Content_Types].xml and _rels/.rels.\n"
        "Classification is based on entry names, not full validation."
    )
    return result
