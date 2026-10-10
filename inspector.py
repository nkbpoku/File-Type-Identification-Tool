from pathlib import Path
import shutil
import stat
import subprocess
from filename_checks import check_filename


FORMAT_EXTENSIONS = {
    "image/png": (".png",),
    "image/jpeg": (".jpg", ".jpeg", ".jpe"),
    "image/gif": (".gif",),
    "image/webp": (".webp",),
    "image/tiff": (".tif", ".tiff"),
    "image/bmp": (".bmp",),
    "image/x-ms-bmp": (".bmp",),
    "image/vnd.microsoft.icon": (".ico",),
    "application/pdf": (".pdf",),
    "application/gzip": (".gz", ".tgz"),
    "application/x-gzip": (".gz", ".tgz"),
    "application/x-7z-compressed": (".7z",),
    "application/x-rar": (".rar",),
    "application/vnd.rar": (".rar",),
    "audio/mpeg": (".mp3",),
    "audio/flac": (".flac",),
    "audio/x-flac": (".flac",),
    "audio/x-wav": (".wav",),
    "audio/wav": (".wav",),
    "video/mp4": (".mp4", ".m4v"),
    "video/quicktime": (".mov",),
    "application/vnd.openxmlformats-officedocument."
    "wordprocessingml.document": (".docx",),
    "application/vnd.openxmlformats-officedocument."
    "spreadsheetml.sheet": (".xlsx",),
    "application/vnd.openxmlformats-officedocument."
    "presentationml.presentation": (".pptx",),
}


def run_detector(tool, path, mime=False):
    command = [tool, "-b"]

    if mime:
        command.append("--mime-type")

    # Arguments are passed directly, without a shell.
    command.extend(["--", str(path)])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired as error:
        raise OSError("File identification took too long.") from error
    except subprocess.CalledProcessError as error:
        raise OSError(
            error.stderr.strip() or "File identification failed."
        ) from error

    return result.stdout.strip()


def compare_extension(extension, mime_type):
    if mime_type in ("application/zip", "application/x-zip"):
        return (
            ".zip (container; may also contain another format)",
            "Inconclusive — ZIP containers are used by several formats",
        )

    if mime_type.startswith("text/"):
        return (
            "Depends on the text format",
            "Inconclusive — text can represent several file types",
        )

    if mime_type in (
        "application/octet-stream",
        "application/x-empty",
        "inode/x-empty",
    ):
        return "Unable to determine", "Inconclusive"

    extensions = FORMAT_EXTENSIONS.get(mime_type)

    if extensions is None:
        return (
            "Not mapped yet",
            "Inconclusive — no extension comparison rule for this format",
        )

    suggested = " or ".join(extensions)
    comparison = (
        "Extension matches the signature"
        if extension in extensions
        else "Extension mismatch"
    )

    return suggested, comparison


def inspect_pe(path, size):
    """Check basic PE headers. This does not fully validate a PE file."""
    with path.open("rb") as file:
        dos_header = file.read(64)

        if len(dos_header) < 64 or dos_header[:2] != b"MZ":
            return None

        # The DOS header points to the PE header.
        pe_offset = int.from_bytes(dos_header[60:64], "little")

        if pe_offset < 64 or pe_offset + 24 > size:
            return None

        file.seek(pe_offset)
        pe_header = file.read(24)

        if len(pe_header) != 24 or pe_header[:4] != b"PE\x00\x00":
            return None

        machine = int.from_bytes(pe_header[4:6], "little")
        section_count = int.from_bytes(pe_header[6:8], "little")
        optional_size = int.from_bytes(pe_header[20:22], "little")
        characteristics = int.from_bytes(pe_header[22:24], "little")

        table_end = (
            pe_offset + 24 + optional_size + section_count * 40
        )

        if section_count == 0 or table_end > size:
            return None

        if optional_size < 70:
            return None

        optional_header = file.read(optional_size)

        if len(optional_header) != optional_size:
            return None

        magic = int.from_bytes(optional_header[:2], "little")
        subsystem = int.from_bytes(optional_header[68:70], "little")

        if magic == 0x10B:
            pe_format = "PE32"
            minimum_size = 96
        elif magic == 0x20B:
            pe_format = "PE32+"
            minimum_size = 112
        else:
            return None

        if optional_size < minimum_size:
            return None

        # IMAGE_FILE_EXECUTABLE_IMAGE.
        if not characteristics & 0x0002:
            return None

        architectures = {
            0x014C: "x86",
            0x8664: "x64",
            0x01C4: "ARM",
            0xAA64: "ARM64",
        }
        architecture = architectures.get(
            machine, f"machine code 0x{machine:04x}"
        )

        if subsystem in (10, 11, 12, 13):
            kind = "EFI executable candidate"
            extensions = (".efi",)
        elif subsystem == 1:
            kind = "Native PE image / driver candidate"
            extensions = (".sys", ".exe", ".dll")
        elif characteristics & 0x2000:
            kind = "Windows DLL candidate"
            extensions = (
                ".dll", ".ocx", ".cpl", ".pyd", ".acm", ".ax",
                ".drv", ".ime", ".mui", ".tsp", ".msstyles",
            )
        else:
            kind = "Windows executable candidate"
            extensions = (".exe", ".scr")

        return {
            "description": f"{kind} ({pe_format}, {architecture})",
            "extensions": extensions,
            "evidence": (
                "MZ signature at byte 0.\n"
                f"PE signature at byte {pe_offset}.\n"
                f"Format: {pe_format}; architecture: {architecture}.\n"
                f"Declared sections: {section_count}.\n"
                f"Characteristics: 0x{characteristics:04x}.\n"
                f"Subsystem: {subsystem}.\n"
                "Basic header checks passed. Section contents, imports, "
                "digital signatures and behaviour were not checked.\n"
                "Suggested extensions are common examples, not an "
                "exhaustive list or recovered filename history."
            ),
        }


def inspect_file(file_path):
    path = Path(file_path).expanduser().resolve(strict=True)
    file_info = path.stat()

    if not stat.S_ISREG(file_info.st_mode):
        raise OSError("Please select a regular file.")

    with path.open("rb") as file:
        header = file.read(32)

    extension = path.suffix.lower()
    pe_details = inspect_pe(path, file_info.st_size)

    if pe_details is not None:
        detected_format = pe_details["description"]
        mime_type = "application/vnd.microsoft.portable-executable"
        suggested_extension = " or ".join(pe_details["extensions"])

        comparison = (
            "Extension matches the signature"
            if extension in pe_details["extensions"]
            else "Extension mismatch"
        )

        evidence = pe_details["evidence"]

    else:
        tool = (
            "/usr/bin/file"
            if Path("/usr/bin/file").is_file()
            else shutil.which("file")
        )

        if tool is None:
            raise OSError(
                "Broad identification requires the 'file' tool. "
                "Windows broad-format support is not configured yet."
            )

        detected_format = run_detector(tool, path)
        mime_type = run_detector(tool, path, mime=True)

        suggested_extension, comparison = compare_extension(
            extension, mime_type
        )

        evidence = (
            "Identified using the system file tool's content rules.\n"
            f"Content category (MIME): {mime_type}\n"
            "This is content identification, not full structural "
            "validation."
        )

        if header.startswith(b"MZ"):
            evidence += (
                "\nThe file starts with MZ, but our basic PE check "
                "did not pass. This may be another MZ-based format "
                "or an incomplete or malformed PE file."
            )

    evidence += (
        "\nFirst 32 bytes, hexadecimal: "
        + (header.hex(" ") if header else "Empty file")
    )

    return {
        "name": path.name,
        "location": str(path),
        "extension": extension or "No extension",
        "size_bytes": file_info.st_size,
        "detected_format": detected_format,
        "suggested_extension": suggested_extension,
        "comparison": comparison,
        "original_name": "Unknown — no rename history available",
        "evidence": evidence,
        "mime_type": mime_type,
        "filename_findings": check_filename(path),
    }