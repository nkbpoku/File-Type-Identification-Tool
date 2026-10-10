import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from tkinterdnd2 import TkinterDnD, DND_FILES
from inspector import inspect_file


BACKGROUND = "#f5f5f7"
PANEL = "#ffffff"
TEXT = "#171717"
MUTED = "#626975"
DROP_EMPTY = "#e8ebef"
DROP_SELECTED = "#dceee3"
DROP_FLASH = "#b8dfc5"
BUTTON = "#e5e7eb"
BUTTON_PRESSED = "#cbd0d8"

ASSETS = Path(__file__).resolve().parent / "assets"

selected_file = None
busy = False


def readable_size(size):
    value = float(size)

    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            number = f"{value:.2f}".rstrip("0").rstrip(".")
            return f"{number} {unit}"
        value /= 1000


def readable_location(file_path):
    folder = Path(file_path).parent

    try:
        relative = folder.relative_to(Path.home())
    except ValueError:
        return " → ".join(folder.parts)

    if not relative.parts:
        return "Home folder"

    return "Home → " + " → ".join(relative.parts)


def friendly_type(details):
    names = {
        "application/pdf": "PDF document",
        "image/png": "PNG image",
        "image/jpeg": "JPEG image",
        "image/gif": "GIF image",
        "image/webp": "WebP image",
        "image/tiff": "TIFF image",
        "image/bmp": "BMP image",
        "image/x-ms-bmp": "BMP image",
        "application/zip": "ZIP container",
        "application/gzip": "GZIP compressed file",
        "application/x-gzip": "GZIP compressed file",
        "application/x-7z-compressed": "7-Zip archive",
        "audio/mpeg": "MP3 audio",
        "audio/flac": "FLAC audio",
        "audio/x-flac": "FLAC audio",
        "audio/wav": "WAV audio",
        "audio/x-wav": "WAV audio",
        "video/mp4": "MP4 video",
        "video/quicktime": "QuickTime video",
        "text/plain": "Plain text",
    }

    return names.get(
        details.get("mime_type"),
        details["detected_format"],
    )


def describe_result(details):
    comparison = details["comparison"]

    if comparison == "Extension matches the signature":
        return (
            f"The detected contents match the file's "
            f"{details['extension']} extension."
        )

    if comparison == "Extension mismatch":
        if details["extension"] == "No extension":
            return (
                "This file has no extension. Its contents suggest "
                f"{friendly_type(details)}."
            )

        return (
            f"The name ends in {details['extension']}, but the "
            f"contents suggest {friendly_type(details)}. "
            "The extension may have been changed or assigned "
            "incorrectly. Its previous name is unknown."
        )

    return (
        "The current checks cannot confidently compare "
        "this file's contents with its extension."
    )


def load_small_icon(filename):
    try:
        image = tk.PhotoImage(file=str(ASSETS / filename))
    except tk.TclError:
        return None

    factor = max(
        1,
        (max(image.width(), image.height()) + 47) // 48,
    )
    return image.subsample(factor, factor)


def show_result_icon(kind):
    result_icon.delete("all")

    if kind == "match":
        image = check_icon
        colour = "#009c00"
        caption = "Extension matches; no filename concerns found."
    elif kind == "concern":
        image = cross_icon
        colour = "#ff3333"
        caption = "Mismatch or filename concern - review the details."
    else:
        image = None
        colour = "#7a8089"
        caption = "Unable to confirm — review the details."

    if image is not None:
        result_icon.create_image(28, 28, image=image)
    else:
        result_icon.create_oval(
            4, 4, 52, 52,
            fill=colour,
            outline="",
        )

        if kind == "match":
            result_icon.create_line(
                15, 28, 24, 37, 41, 19,
                fill="white",
                width=6,
                capstyle=tk.ROUND,
                joinstyle=tk.ROUND,
            )
        elif kind == "concern":
            for coordinates in (
                (18, 18, 38, 38),
                (18, 38, 38, 18),
            ):
                result_icon.create_line(
                    *coordinates,
                    fill="white",
                    width=6,
                    capstyle=tk.ROUND,
                )
        else:
            result_icon.create_text(
                28, 28,
                text="?",
                fill="white",
                font=("Arial", 25, "bold"),
            )

    result_caption.configure(text=caption)


def make_button(parent, text, command):
    button = tk.Label(
        parent,
        text=text,
        font=("Arial", 13, "bold"),
        bg=BUTTON,
        fg=TEXT,
        padx=22,
        pady=11,
        relief="raised",
        borderwidth=2,
        cursor="hand2",
        takefocus=True,
    )
    button.enabled = True

    def reset():
        button.configure(bg=BUTTON, relief="raised")

    def press(event):
        if button.enabled:
            button.focus_set()
            button.configure(bg=BUTTON_PRESSED, relief="sunken")

    def release(event):
        reset()
        inside = (
            0 <= event.x < button.winfo_width()
            and 0 <= event.y < button.winfo_height()
        )
        if button.enabled and inside:
            command()

    def keyboard_activate(event):
        if button.enabled:
            button.configure(bg=BUTTON_PRESSED, relief="sunken")
            button.after(100, reset)
            command()
        return "break"

    button.bind("<ButtonPress-1>", press)
    button.bind("<ButtonRelease-1>", release)
    button.bind("<Leave>", lambda event: reset())
    button.bind("<Return>", keyboard_activate)
    button.bind("<space>", keyboard_activate)
    button.bind(
        "<FocusIn>",
        lambda event: button.configure(highlightthickness=2),
    )
    button.bind(
        "<FocusOut>",
        lambda event: button.configure(highlightthickness=0),
    )
    button.configure(
        highlightbackground=MUTED,
        highlightcolor=MUTED,
    )
    return button


def enable_button(button, enabled):
    button.enabled = enabled
    button.configure(
        fg=TEXT if enabled else "#9298a1",
        cursor="hand2" if enabled else "arrow",
    )


def select_file(file_path):
    global selected_file

    path = Path(file_path)

    if not path.is_file():
        messagebox.showerror(
            "Choose a file",
            "Please select a regular file.",
        )
        return

    selected_file = str(path)
    filename.set(path.name)
    status.set("File selected. Click Identify when ready.")
    select_button.configure(text="Clear")
    enable_button(identify_button, True)
    drop_area.configure(
        text=f"File selected\n\n{path.name}",
        bg=DROP_FLASH,
    )
    window.after(180, finish_drop_feedback)


def finish_drop_feedback():
    if selected_file is not None:
        drop_area.configure(bg=DROP_SELECTED)


def choose_or_clear():
    if busy:
        return

    if selected_file is not None:
        clear_file()
        return

    file_path = filedialog.askopenfilename(title="Choose a file")
    if file_path:
        select_file(file_path)


def drop_file(event):
    if busy:
        return

    paths = window.tk.splitlist(event.data)

    if len(paths) != 1:
        messagebox.showinfo(
            "One file at a time",
            "Please drop one file at a time.",
        )
        return

    select_file(paths[0])


def clear_file():
    global selected_file

    if busy:
        return

    selected_file = None
    filename.set("")
    status.set("Choose or drop a file to get started.")
    select_button.configure(text="Choose File")
    enable_button(identify_button, False)
    enable_button(select_button, True)
    drop_area.configure(text="Drop file here", bg=DROP_EMPTY)

    results_frame.pack_forget()
    selection_frame.pack(fill="both", expand=True)

    report_box.configure(state="normal")
    report_box.delete("1.0", tk.END)
    report_box.configure(state="disabled")
    result_icon.delete("all")
    result_caption.configure(text="")


def display_report(details):
    findings = details.get("filename_findings")
    comparison = details["comparison"]

    has_concern = any(
        finding["level"] in {"Warning", "Notice"}
        for finding in (findings or [])
    )

    if comparison == "Extension mismatch" or has_concern:
        show_result_icon("concern")
    elif (
        comparison == "Extension matches the signature"
        and findings is not None
    ):
        show_result_icon("match")
    else:
        show_result_icon("unknown")

    if findings is None:
        name_check = "Filename check unavailable."
    elif not findings:
        name_check = (
            "No misleading filename patterns found "
            "by the current checks."
        )
    else:
        name_check = "\n\n".join(
            finding["message"] for finding in findings
        )

    report = (
        f"File: {details['name']}\n\n"
        f"Size: {readable_size(details['size_bytes'])}\n\n"
        f"Detected type: {friendly_type(details)}\n\n"
        f"Current extension: {details['extension']}\n\n"
        f"Expected extension: {details['suggested_extension']}\n\n"
        f"Result: {describe_result(details)}\n\n"
        f"Name check: {name_check}\n\n"
        f"Saved in: {readable_location(details['location'])}\n\n"
        "These checks don't confirm whether a file is safe to open."
    )

    report_box.configure(state="normal")
    report_box.delete("1.0", tk.END)
    report_box.insert("1.0", report)
    report_box.yview_moveto(0)
    report_box.configure(state="disabled")


def identify_file():
    global busy

    if selected_file is None or busy:
        return

    busy = True
    status.set("Reading file…")
    enable_button(identify_button, False)
    enable_button(select_button, False)
    window.after(100, show_results)


def show_results():
    global busy

    try:
        details = inspect_file(selected_file)
    except OSError as error:
        status.set("Could not read the file. Clear it and try again.")
        messagebox.showerror("Cannot read file", str(error))
        return
    finally:
        busy = False
        enable_button(identify_button, selected_file is not None)
        enable_button(select_button, True)

    display_report(details)
    selection_frame.pack_forget()
    results_frame.pack(fill="both", expand=True)
    status.set("Inspection complete.")


window = TkinterDnD.Tk()
window.title("File Type Identification Tool")
window.geometry("1000x780")
window.minsize(760, 620)
window.configure(bg=BACKGROUND)

check_icon = load_small_icon("check.png")
cross_icon = load_small_icon("cross.png")

filename = tk.StringVar()
status = tk.StringVar(value="Choose or drop a file to get started.")

panel = tk.Frame(window, bg=PANEL)
panel.pack(fill="both", expand=True, padx=24, pady=24)

heading = tk.Label(
    panel,
    text="File Type Identification Tool",
    font=("Arial", 26, "bold"),
    bg=PANEL,
    fg=TEXT,
)
heading.pack(pady=(28, 14))

status_label = tk.Label(
    panel,
    textvariable=status,
    font=("Arial", 12),
    bg=PANEL,
    fg=MUTED,
)
status_label.pack(pady=(0, 12))

selection_frame = tk.Frame(panel, bg=PANEL)
selection_frame.pack(fill="both", expand=True)

file_row = tk.Frame(selection_frame, bg=PANEL)
file_row.pack(fill="x", padx=60, pady=15)

filename_box = tk.Entry(
    file_row,
    textvariable=filename,
    state="readonly",
    readonlybackground=PANEL,
    fg=TEXT,
    font=("Arial", 14),
    relief="solid",
    borderwidth=1,
)
filename_box.pack(side="left", fill="x", expand=True, ipady=11)

select_button = make_button(file_row, "Choose File", choose_or_clear)
select_button.pack(side="right", padx=(8, 0))

drop_area = tk.Label(
    selection_frame,
    text="Drop file here",
    bg=DROP_EMPTY,
    fg=TEXT,
    font=("Arial", 15),
    width=24,
    height=9,
    wraplength=240,
)
drop_area.pack(pady=20)
drop_area.drop_target_register(DND_FILES)
drop_area.dnd_bind("<<Drop>>", drop_file)

identify_button = make_button(selection_frame, "Identify", identify_file)
identify_button.pack(pady=(10, 25))
enable_button(identify_button, False)

results_frame = tk.Frame(panel, bg=PANEL)

# Keep Done visible even when the report needs scrolling.
footer = tk.Frame(results_frame, bg=PANEL)
footer.pack(side="bottom", fill="x", padx=35, pady=(10, 25))

done_button = make_button(footer, "Done", clear_file)
done_button.pack(side="right")

result_icon = tk.Canvas(
    results_frame,
    width=56,
    height=56,
    bg=PANEL,
    highlightthickness=0,
    borderwidth=0,
)
result_icon.pack(pady=(0, 5))

result_caption = tk.Label(
    results_frame,
    text="",
    bg=PANEL,
    fg=MUTED,
    font=("Arial", 11),
    wraplength=650,
)
result_caption.pack(pady=(0, 16))

report_container = tk.Frame(results_frame, bg=PANEL)
report_container.pack(
    fill="both",
    expand=True,
    padx=35,
    pady=(0, 10),
)

scrollbar = tk.Scrollbar(report_container)
scrollbar.pack(side="right", fill="y")

report_box = tk.Text(
    report_container,
    wrap="word",
    font=("Arial", 13),
    bg=PANEL,
    fg=TEXT,
    padx=12,
    pady=10,
    spacing2=4,
    spacing3=8,
    relief="flat",
    borderwidth=0,
    highlightthickness=0,
    yscrollcommand=scrollbar.set,
    state="disabled",
)
report_box.pack(side="left", fill="both", expand=True)
scrollbar.configure(command=report_box.yview)

window.mainloop()