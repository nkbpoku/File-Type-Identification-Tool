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

selected_file = None


def readable_size(size):
    value = float(size)

    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            number = f"{value:.2f}".rstrip("0").rstrip(".")
            return f"{number} {unit}"

        value /= 1000


def make_button(parent, text, command):
    """A styled button with visible press feedback."""
    button = tk.Label(
        parent,
        text=text,
        font=("Arial", 14, "bold"),
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

    def press(event):
        if button.enabled:
            button.configure(bg=BUTTON_PRESSED, relief="sunken")

    def release(event):
        button.configure(bg=BUTTON, relief="raised")

        if not button.enabled:
            return

        inside = (
            0 <= event.x < button.winfo_width()
            and 0 <= event.y < button.winfo_height()
        )

        if inside:
            command()

    def keyboard_activate(event):
        if button.enabled:
            button.configure(bg=BUTTON_PRESSED, relief="sunken")
            button.after(
                100,
                lambda: button.configure(bg=BUTTON, relief="raised"),
            )
            command()

        return "break"

    button.bind("<ButtonPress-1>", press)
    button.bind("<ButtonRelease-1>", release)
    button.bind(
        "<Leave>",
        lambda event: button.configure(bg=BUTTON, relief="raised"),
    )
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
    button.configure(highlightbackground=MUTED, highlightcolor=MUTED)

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

    selected_file = None
    filename.set("")
    status.set("Choose or drop a file to get started.")

    select_button.configure(text="Choose File")
    enable_button(identify_button, False)
    enable_button(select_button, True)

    drop_area.configure(
        text="Drop file here",
        bg=DROP_EMPTY,
    )

    results_frame.pack_forget()
    selection_frame.pack(fill="both", expand=True)
    set_report("")


def describe_result(details):
    comparison = details["comparison"]

    if comparison == "Extension mismatch":
        return (
            f"The name ends in {details['extension']}, but the contents "
            f"suggest {details['detected_format']}.\n"
            "It may have been renamed or given the wrong extension. "
            "These checks cannot establish its previous name."
        )

    if comparison == "Extension matches the signature":
        return "The filename extension matches the signature found."

    return (
        "There is not enough evidence to confirm whether the "
        "filename extension matches the contents."
    )


def set_report(text):
    report_box.configure(state="normal")
    report_box.delete("1.0", tk.END)
    report_box.insert("1.0", text)
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
        enable_button(identify_button, True)
        enable_button(select_button, True)

    report = (
        f"File name: {details['name']}\n\n"
        f"Size: {readable_size(details['size_bytes'])}\n\n"
        f"File type found: {details['detected_format']}\n\n"
        f"Filename extension: {details['extension']}\n\n"
        f"Suggested extension: {details['suggested_extension']}\n\n"
        f"What we found\n{describe_result(details)}\n\n"
        f"Location: {details['location']}\n\n"
        f"How we checked\n{details['evidence']}\n\n"
        "File-type identification does not establish whether "
        "a file is safe to open."
    )

    set_report(report)
    selection_frame.pack_forget()
    results_frame.pack(fill="both", expand=True)
    status.set("Inspection complete.")


window = TkinterDnD.Tk()
window.title("File Type Identification Tool")
window.geometry("1000x720")
window.minsize(760, 620)
window.configure(bg=BACKGROUND)

busy = False
filename = tk.StringVar()
status = tk.StringVar(value="Choose or drop a file to get started.")

panel = tk.Frame(window, bg=PANEL)
panel.pack(fill="both", expand=True, padx=24, pady=24)

heading = tk.Label(
    panel,
    text="File Type Identification Tool",
    font=("Arial", 28, "bold"),
    bg=PANEL,
    fg=TEXT,
)
heading.pack(pady=(35, 25))

status_label = tk.Label(
    panel,
    textvariable=status,
    font=("Arial", 12),
    bg=PANEL,
    fg=MUTED,
)
status_label.pack(pady=(0, 20))

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
filename_box.pack(
    side="left",
    fill="x",
    expand=True,
    ipady=11,
)

select_button = make_button(
    file_row,
    "Choose File",
    choose_or_clear,
)
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

identify_button = make_button(
    selection_frame,
    "Identify",
    identify_file,
)
identify_button.pack(pady=(10, 25))
enable_button(identify_button, False)

results_frame = tk.Frame(panel, bg=PANEL)

# Pack the footer first so Done stays visible below the report.
footer = tk.Frame(results_frame, bg=PANEL)
footer.pack(side="bottom", fill="x", padx=35, pady=(10, 25))

done_button = make_button(footer, "Done", clear_file)
done_button.pack(side="right")

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
    pady=12,
    relief="flat",
    borderwidth=0,
    highlightthickness=0,
    yscrollcommand=scrollbar.set,
    state="disabled",
)
report_box.pack(side="left", fill="both", expand=True)
scrollbar.configure(command=report_box.yview)

window.mainloop()