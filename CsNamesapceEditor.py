#!/usr/bin/env python3
import os
import re
import sys
import time
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# Regexes to catch both C# namespace styles:
# 1) File-scoped:   namespace Foo.Bar;
FILE_SCOPED_NS = re.compile(
    r'(?m)^(?P<indent>\s*)namespace\s+(?P<name>[A-Za-z_][\w\.]*)\s*;\s*$'
)

# 2) Block-scoped:  namespace Foo.Bar {   (brace may be on same or next line)
BLOCK_SCOPED_NS = re.compile(
    r'(?m)^(?P<indent>\s*)namespace\s+(?P<name>[A-Za-z_][\w\.]*)\s*(?P<brace>\{|\r?\n\s*\{)'
)

CS_GLOB = "*.cs"


def find_cs_files(root: Path, recursive: bool = True):
    if recursive:
        for p in root.rglob(CS_GLOB):
            if p.is_file():
                yield p
    else:
        for p in root.glob(CS_GLOB):
            if p.is_file():
                yield p


def detect_namespaces(text: str):
    """
    Return list of matches (style, MatchObject).
    We keep both styles; some files can have multiple (rare, but possible).
    """
    matches = []
    for m in FILE_SCOPED_NS.finditer(text):
        matches.append(("file-scoped", m))
    for m in BLOCK_SCOPED_NS.finditer(text):
        matches.append(("block", m))
    return matches


def replace_namespaces(text: str, new_ns: str):
    """
    Replace file- and block-scoped namespaces with new_ns.
    Returns (new_text, num_replacements).
    """
    replaced = 0

    def repl_file(m: re.Match):
        nonlocal replaced
        replaced += 1
        return f"{m.group('indent')}namespace {new_ns};"

    def repl_block(m: re.Match):
        nonlocal replaced
        brace = m.group('brace')
        return f"{m.group('indent')}namespace {new_ns}{brace}"

    text = FILE_SCOPED_NS.sub(repl_file, text)
    text = BLOCK_SCOPED_NS.sub(repl_block, text)
    return text, replaced


def read_text_guess_encoding(path: Path):
    """
    Keep it simple: try utf-8-sig, fallback to utf-8 (replace),
    then latin-1 as a last resort.
    Return (text, encoding_used)
    """
    try:
        txt = path.read_text(encoding="utf-8-sig")
        return txt, "utf-8-sig"
    except UnicodeDecodeError:
        try:
            txt = path.read_text(encoding="utf-8", errors="replace")
            return txt, "utf-8"
        except UnicodeDecodeError:
            txt = path.read_text(encoding="latin-1", errors="replace")
            return txt, "latin-1"


def write_text_with_encoding(path: Path, text: str, encoding: str):
    # If we detected utf-8-sig, preserve the BOM by writing with utf-8-sig
    path.write_text(text, encoding=encoding, errors="replace")


class NamespaceTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("C# Namespace Bulk Editor")
        self.geometry("900x600")

        self.folder_var = tk.StringVar()
        self.namespace_var = tk.StringVar()
        self.recurse_var = tk.BooleanVar(value=True)
        self.backup_var = tk.BooleanVar(value=True)

        self._build_ui()

        self.files = []  # list of Path
        self.scan_results = {}  # path -> dict(info)
        self._worker = None

    def _build_ui(self):
        frm_top = ttk.Frame(self, padding=10)
        frm_top.pack(side=tk.TOP, fill=tk.X)

        # Folder picker
        ttk.Label(frm_top, text="Folder:").grid(row=0, column=0, sticky="w")
        ent_folder = ttk.Entry(frm_top, textvariable=self.folder_var)
        ent_folder.grid(row=0, column=1, sticky="ew", padx=6)
        btn_browse = ttk.Button(frm_top, text="Browse…", command=self.pick_folder)
        btn_browse.grid(row=0, column=2, padx=4)

        frm_top.columnconfigure(1, weight=1)

        # Namespace
        ttk.Label(frm_top, text="New namespace:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ent_ns = ttk.Entry(frm_top, textvariable=self.namespace_var)
        ent_ns.grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))

        # Options
        opt_frame = ttk.Frame(frm_top)
        opt_frame.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(opt_frame, text="Recurse into subfolders", variable=self.recurse_var).pack(side=tk.LEFT)
        ttk.Checkbutton(opt_frame, text="Create .bak backups", variable=self.backup_var).pack(side=tk.LEFT, padx=(12, 0))

        # Actions
        btn_frame = ttk.Frame(frm_top)
        btn_frame.grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        ttk.Button(btn_frame, text="Scan", command=self.scan_folder).pack(side=tk.LEFT)
        self.btn_apply = ttk.Button(btn_frame, text="Apply Changes", command=self.apply_changes, state=tk.DISABLED)
        self.btn_apply.pack(side=tk.LEFT, padx=8)

        # Progress
        self.progress = ttk.Progressbar(frm_top, mode="determinate", length=300)
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 0))

        # Treeview for results
        tree_frame = ttk.Frame(self, padding=(10, 6, 10, 6))
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("file", "style", "current_ns", "status")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=12)
        self.tree.heading("file", text="File")
        self.tree.heading("style", text="Style")
        self.tree.heading("current_ns", text="Detected Namespace(s)")
        self.tree.heading("status", text="Status")
        self.tree.column("file", width=400, anchor="w")
        self.tree.column("style", width=100, anchor="w")
        self.tree.column("current_ns", width=240, anchor="w")
        self.tree.column("status", width=120, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        # Log
        log_frame = ttk.LabelFrame(self, text="Log", padding=6)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.log = ScrolledText(log_frame, height=8, wrap="word")
        self.log.pack(fill=tk.BOTH, expand=True)

    def pick_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def log_line(self, msg: str):
        self.log.insert(tk.END, msg.rstrip() + "\n")
        self.log.see(tk.END)
        self.update_idletasks()

    def scan_folder(self):
        root = Path(self.folder_var.get().strip())
        if not root or not root.exists():
            messagebox.showerror("Nope", "Pick a valid folder.")
            return

        self.tree.delete(*self.tree.get_children())
        self.files = list(find_cs_files(root, recursive=self.recurse_var.get()))
        self.scan_results.clear()

        total = len(self.files)
        self.progress.configure(maximum=max(1, total), value=0)
        self.log_line(f"Scanning {total} .cs files under: {root}")

        changed_candidates = 0

        for i, p in enumerate(self.files, start=1):
            try:
                text, enc = read_text_guess_encoding(p)
            except Exception as e:
                self.tree.insert("", tk.END, values=(str(p), "", "", f"Read error: {e}"))
                continue

            matches = detect_namespaces(text)
            styles = ",".join(sorted({m[0] for m in matches})) if matches else ""
            found_names = ", ".join(sorted({m[1].group('name') for m in matches})) if matches else ""

            status = "ok"
            if not matches:
                status = "no namespace"

            self.scan_results[p] = {
                "encoding": enc,
                "matches": matches,
                "found_names": found_names,
            }

            if matches:
                changed_candidates += 1

            self.tree.insert("", tk.END, values=(str(p.relative_to(root)), styles, found_names, status))
            self.progress["value"] = i
            self.update_idletasks()

        self.log_line(f"Scan complete. {changed_candidates} files contain namespace declarations.")
        self.btn_apply.configure(state=tk.NORMAL if changed_candidates > 0 else tk.DISABLED)

    def apply_changes(self):
        new_ns = self.namespace_var.get().strip()
        if not new_ns:
            messagebox.showerror("Nope", "Enter a new namespace.")
            return
        if not self.scan_results:
            messagebox.showerror("Nope", "Scan first.")
            return

        if not messagebox.askyesno("Confirm", f"Replace namespaces with:\n\n    {new_ns}\n\nProceed?"):
            return

        self.btn_apply.configure(state=tk.DISABLED)

        def worker():
            total = len(self.scan_results)
            done = 0
            replaced_files = 0
            total_replacements = 0
            tstamp = time.strftime("%Y%m%d_%H%M%S")

            for p, info in self.scan_results.items():
                done += 1
                matches = info["matches"]
                if not matches:
                    self._set_row_status(p, "skipped")
                    self._set_progress(done, total)
                    continue

                try:
                    text, enc = read_text_guess_encoding(p)
                    new_text, count = replace_namespaces(text, new_ns)

                    if count > 0 and new_text != text:
                        if self.backup_var.get():
                            bak = p.with_suffix(p.suffix + f".bak.{tstamp}")
                            try:
                                bak.write_text(text, encoding=enc, errors="replace")
                            except Exception:
                                # if backup fails, still attempt to write new content, but log it
                                self.log_line(f"[WARN] Backup failed for {p}")

                        write_text_with_encoding(p, new_text, enc)
                        replaced_files += 1
                        total_replacements += count
                        self._set_row_status(p, f"changed ({count})")
                        self.log_line(f"Updated {p} [{enc}] -> {count} replacement(s)")
                    else:
                        self._set_row_status(p, "unchanged")
                except Exception as e:
                    self._set_row_status(p, f"ERROR: {e}")
                    self.log_line(f"[ERROR] {p}: {e}")

                self._set_progress(done, total)

            self.log_line(f"Done. Files changed: {replaced_files}, total replacements: {total_replacements}.")
            self.btn_apply.configure(state=tk.NORMAL)

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _set_progress(self, done, total):
        self.progress.configure(maximum=max(1, total), value=done)
        self.update_idletasks()

    def _set_row_status(self, path: Path, status: str):
        # Update status cell of the matching row
        for iid in self.tree.get_children(""):
            vals = self.tree.item(iid, "values")
            # vals[0] is relative path shown; so compare suffix match
            if os.path.normpath(vals[0]).endswith(os.path.normpath(str(path.name))):
                # set only the status column
                new_vals = list(vals)
                new_vals[3] = status
                self.tree.item(iid, values=new_vals)
                break


def main():
    # Windows scaling fix (optional nicety)
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    app = NamespaceTool()
    app.mainloop()


if __name__ == "__main__":
    main()
