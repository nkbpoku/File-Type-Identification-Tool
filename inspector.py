from pathlib import Path
import shutil
import stat
import subprocess

from office_checks import inspect_office_container
from filename_checks import check_filename
from outcomes import check_result, summarise_checks


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
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": (".docx",),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": (".xlsx",),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": (".pptx",),
}


def run_detector(tool, path, mime=False):
    command = [tool, "-b"]
    if mime:
        command.append("--mime-type")
    command.extend(["--", str(path)])
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            check=True, timeout=5,
        )
    except subprocess.TimeoutExpired as error:
        raise OSError("File identification took too long.") from error
    except subprocess.CalledProcessError as error:
        raise OSError(error.stderr.strip() or "File identification failed.") from error
    return result.stdout.strip()


def compare_known_extension(extension, extensions):
    if extension in extensions:
        result = check_result(
            "consistent", "EXTENSION_MATCH",
            "The current extension is consistent with the detected format "
            "within this check's scope. This does not establish file safety.",
        )
        comparison = "Extension matches the signature"
    else:
        result = check_result(
            "finding", "EXTENSION_MISMATCH",
            "The current extension is not among the expected extensions "
            "for the detected format. Previous names cannot be recovered "
            "by this check; a mismatch alone does not prove malware.",
        )
        comparison = "Extension mismatch"
    return " or ".join(extensions), comparison, result


def compare_extension(extension, mime_type):
    if mime_type in {
        "application/zip", "application/x-zip", "application/x-zip-compressed"
    }:
        suggested = ".zip (container; several formats use ZIP)"
        message = "ZIP containers are used by several formats; the extension match is inconclusive."
    elif mime_type.startswith("text/"):
        suggested = "Depends on the text format"
        message = "Text can represent several formats; the extension match is inconclusive."
    elif mime_type in {
        "application/octet-stream", "application/x-empty", "inode/x-empty"
    }:
        suggested = "Unable to determine"
        message = "The detected content category does not establish a specific format."
    elif mime_type in FORMAT_EXTENSIONS:
        return compare_known_extension(extension, FORMAT_EXTENSIONS[mime_type])
    else:
        suggested = "Not mapped yet"
        message = "No extension comparison rule is available for this detected format."
    return suggested, "Inconclusive", check_result(
        "incomplete", "EXTENSION_UNCONFIRMED", message,
    )


def inspect_pe(path, size):
    """Basic PE header checks only, without executing the file."""
    with path.open("rb") as file:
        dos_header = file.read(64)
        if len(dos_header) < 64 or dos_header[:2] != b"MZ":
            return None
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
        table_end = pe_offset + 24 + optional_size + section_count * 40
        if section_count == 0 or table_end > size or optional_size < 70:
            return None
        optional_header = file.read(optional_size)
        if len(optional_header) != optional_size:
            return None
        magic = int.from_bytes(optional_header[:2], "little")
        subsystem = int.from_bytes(optional_header[68:70], "little")
        if magic == 0x10B:
            pe_format, minimum_size = "PE32", 96
        elif magic == 0x20B:
            pe_format, minimum_size = "PE32+", 112
        else:
            return None
        if optional_size < minimum_size or not characteristics & 0x0002:
            return None
        architecture = {
            0x014C: "x86", 0x8664: "x64", 0x01C4: "ARM", 0xAA64: "ARM64"
        }.get(machine, f"machine code 0x{machine:04x}")
        if subsystem in (10, 11, 12, 13):
            kind, extensions = "EFI executable candidate", (".efi",)
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
            kind, extensions = "Windows executable candidate", (".exe", ".scr")
        return {
            "description": f"{kind} ({pe_format}, {architecture})",
            "extensions": extensions,
            "evidence": (
                f"MZ signature at byte 0. PE signature at byte {pe_offset}.\n"
                f"Format: {pe_format}; architecture: {architecture}.\n"
                f"Declared sections: {section_count}.\n"
                f"Characteristics: 0x{characteristics:04x}; subsystem: {subsystem}.\n"
                "Basic header checks only. Section contents, imports, signatures "
                "and behaviour were not checked. Expected extensions are common "
                "examples, not exhaustive or recovered filename history."
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
    office_details = inspect_office_container(path)
    content_checks = list(office_details["checks"])

    if pe_details is not None:
        detected_format = pe_details["description"]
        mime_type = "application/vnd.microsoft.portable-executable"
        suggested, comparison, extension_check = compare_known_extension(
            extension, pe_details["extensions"]
        )
        evidence = pe_details["evidence"]
        method = "pe_headers"
    elif office_details["description"] is not None:
        detected_format = office_details["description"]
        mime_type = "application/zip"
        suggested, comparison, extension_check = compare_known_extension(
            extension, office_details["extensions"]
        )
        evidence = "Office candidate identified from ZIP entry names, not full validation."
        method = "office_container"
    else:
        tool = "/usr/bin/file" if Path("/usr/bin/file").is_file() else shutil.which("file")
        if tool is None:
            detected_format, mime_type = "Unknown", "application/octet-stream"
            method = "unavailable"
            suggested, comparison, extension_check = compare_extension(extension, mime_type)
            content_checks.append(check_result(
                "incomplete", "DETECTOR_UNAVAILABLE",
                "Broad identification requires the 'file' tool, which is unavailable.",
            ))
            evidence = "No broad-format detector was available."
        else:
            try:
                detected_format = run_detector(tool, path)
                mime_type = run_detector(tool, path, mime=True)
            except OSError as error:
                detected_format, mime_type = "Unknown", "application/octet-stream"
                content_checks.append(check_result(
                    "incomplete", "DETECTOR_FAILED", str(error),
                ))
            method = "system_file"
            suggested, comparison, extension_check = compare_extension(extension, mime_type)
            evidence = (
                "System file tool content rules; not full structural validation.\n"
                f"Content category (MIME): {mime_type}"
            )
        if header.startswith(b"MZ"):
            content_checks.append(check_result(
                "incomplete", "PE_HEADERS_UNCONFIRMED",
                "The file starts with MZ, but basic PE checks did not pass. "
                "It could be another MZ format or an incomplete PE file.",
            ))

    if office_details["evidence"]:
        evidence += "\n\n" + office_details["evidence"]
    evidence += "\nFirst 32 bytes, hexadecimal: " + (header.hex(" ") or "Empty file")

    # Adapt the existing filename module without changing its public interface.
    filename_findings = check_filename(path)
    filename_checks = []
    for item in filename_findings:
        level = item.get("level")
        status = "finding" if level in {"Warning", "Notice"} else "info"
        if level not in {"Warning", "Notice", "Info"}:
            status = "incomplete"
        filename_checks.append(check_result(
            status, "FILENAME_PATTERN", item["message"],
        ))
    if not filename_checks:
        filename_checks.append(check_result(
            "consistent", "FILENAME_NO_PATTERNS",
            "No misleading filename patterns found by the current checks.",
        ))

    checks = [extension_check, *filename_checks, *content_checks]
    return {
        "name": path.name,
        "location": str(path),
        "extension": extension or "No extension",
        "size_bytes": file_info.st_size,
        "detected_format": detected_format,
        "suggested_extension": suggested,
        "comparison": comparison,
        "original_name": "Unknown — no rename history available",
        "evidence": evidence,
        "mime_type": mime_type,
        "detection_method": method,
        "extension_check": extension_check,
        "filename_findings": filename_findings,
        "filename_checks": filename_checks,
        "content_checks": content_checks,
        # Retain messages for older consumers; new consumers use content_checks.
        "content_findings": [
            item["message"] for item in content_checks
            if item["status"] in {"finding", "incomplete"}
        ],
        "checks": checks,
        "outcome": summarise_checks(checks),
    }
