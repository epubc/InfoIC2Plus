#!/usr/bin/env python3
"""
edit_infoic2plus_gui.py - Desktop GUI editor for Xgpro's InfoIC2Plus.dll
chip database. Requires infoic2plus_lib.py in the same folder.
Pure stdlib (Tkinter) - no extra packages to install.

Only edits/adds/deletes chip *variants* inside EXISTING families. Adding a
brand-new top-level family is not supported (see infoic2plus_lib.py's
docstring for why). Family index 0 ("MY FAVORITES-User") and 172
("Customize") are pre-existing user-customization slots meant for exactly
this kind of addition.

Run:
    python edit_infoic2plus_gui.py [InfoIC2Plus.dll]
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from infoic2plus_lib import InfoIC2PlusDB, FAMILY_COUNT, NAME_MAX_BYTES

FIELD_KEYS = ["algo_id", "flags", "sub_id", "bus_width", "page_size",
              "total_blocks", "spare_size", "nce_pin", "nrb_pin", "pages_per_block"]


class App(tk.Tk):
    def __init__(self, initial_path=None):
        super().__init__()
        self.title("InfoIC2Plus.dll Editor")
        self.geometry("1180x680")

        self.db = None
        self.current_family = None
        self.current_variants = []  # list of (vi, dict) currently shown
        self.dirty = False

        self._build_menu()
        self._build_layout()

        if initial_path:
            self._open(initial_path)

    # ------------------------------------------------------------- menu --
    def _build_menu(self):
        m = tk.Menu(self)
        filem = tk.Menu(m, tearoff=0)
        filem.add_command(label="Open DLL...", command=self._open_dialog)
        filem.add_separator()
        filem.add_command(label="Save As...", command=lambda: self._save(overwrite=False))
        filem.add_command(label="Save (overwrite original, auto-backup)", command=lambda: self._save(overwrite=True))
        filem.add_separator()
        filem.add_command(label="Exit", command=self.destroy)
        m.add_cascade(label="File", menu=filem)
        self.config(menu=m)

    # ----------------------------------------------------------- layout --
    def _build_layout(self):
        root = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        root.pack(fill=tk.BOTH, expand=True)

        # --- left: family list ---
        left = ttk.Frame(root, width=320)
        root.add(left, weight=1)

        ttk.Label(left, text="Families (double-click to load)").pack(anchor="w", padx=4, pady=(4, 0))
        self.family_filter_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.family_filter_var).pack(fill=tk.X, padx=4)
        self.family_filter_var.trace_add("write", lambda *a: self._refresh_family_list())

        self.family_list = tk.Listbox(left)
        self.family_list.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.family_list.bind("<Double-Button-1>", lambda e: self._load_selected_family())

        ttk.Label(left, text="Search chip name (all families)").pack(anchor="w", padx=4)
        search_row = ttk.Frame(left)
        search_row.pack(fill=tk.X, padx=4, pady=(0, 4))
        self.search_var = tk.StringVar()
        ttk.Entry(search_row, textvariable=self.search_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(search_row, text="Search", command=self._do_search).pack(side=tk.LEFT, padx=(4, 0))

        # --- middle: variant list ---
        mid = ttk.Frame(root, width=420)
        root.add(mid, weight=2)

        self.variant_label = ttk.Label(mid, text="(no family loaded)")
        self.variant_label.pack(anchor="w", padx=4, pady=(4, 0))

        columns = ("idx", "name")
        self.variant_tree = ttk.Treeview(mid, columns=columns, show="headings", selectmode="browse")
        self.variant_tree.heading("idx", text="#")
        self.variant_tree.heading("name", text="Chip name")
        self.variant_tree.column("idx", width=50, anchor="center")
        self.variant_tree.column("name", width=340)
        self.variant_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.variant_tree.bind("<<TreeviewSelect>>", lambda e: self._load_selected_variant())

        btn_row = ttk.Frame(mid)
        btn_row.pack(fill=tk.X, padx=4, pady=(0, 4))
        ttk.Button(btn_row, text="Delete selected", command=self._delete_selected).pack(side=tk.LEFT)
        ttk.Button(btn_row, text="Clone as new...", command=self._clone_selected).pack(side=tk.LEFT, padx=(6, 0))

        # --- right: edit form ---
        right = ttk.Frame(root, width=380)
        root.add(right, weight=2)

        form = ttk.LabelFrame(right, text="Edit selected chip")
        form.pack(fill=tk.X, padx=6, pady=6)

        self.form_vars = {}
        row = 0
        ttk.Label(form, text="Name suffix (after family short name)").grid(row=row, column=0, columnspan=2, sticky="w", padx=4, pady=(4, 0))
        row += 1
        self.form_vars["name_suffix"] = tk.StringVar()
        ttk.Entry(form, textvariable=self.form_vars["name_suffix"], width=40).grid(row=row, column=0, columnspan=2, sticky="we", padx=4)
        row += 1
        ttk.Label(form, text="(max %d chars)" % (NAME_MAX_BYTES - 1), foreground="gray").grid(row=row, column=0, columnspan=2, sticky="w", padx=4)
        row += 1

        labels = {
            "algo_id": "Algo ID", "flags": "Flags (hex ok, e.g. 0xC000B700)", "sub_id": "Sub ID",
            "bus_width": "Bus Width (bits)", "page_size": "PageSize (bytes)",
            "total_blocks": "Total Blocks", "spare_size": "SpareSize (bytes, 0-255)",
            "nce_pin": "nCE# Pin (0-255)", "nrb_pin": "nRB# Pin (0-255)",
            "pages_per_block": "Pages Per Block",
        }
        for key in FIELD_KEYS:
            ttk.Label(form, text=labels[key]).grid(row=row, column=0, sticky="w", padx=4, pady=2)
            var = tk.StringVar()
            ttk.Entry(form, textvariable=var, width=20).grid(row=row, column=1, sticky="we", padx=4, pady=2)
            self.form_vars[key] = var
            row += 1

        self.computed_label = ttk.Label(form, text="", foreground="blue", justify="left")
        self.computed_label.grid(row=row, column=0, columnspan=2, sticky="w", padx=4, pady=(6, 4))
        row += 1

        ttk.Button(form, text="Apply edit to selected chip", command=self._apply_edit).grid(
            row=row, column=0, columnspan=2, sticky="we", padx=4, pady=(4, 8))

        form.columnconfigure(1, weight=1)

        self.status = ttk.Label(right, text="Open a DLL from the File menu to begin.", wraplength=360, justify="left")
        self.status.pack(fill=tk.X, padx=6, pady=6)

    # -------------------------------------------------------------- io --
    def _open_dialog(self):
        path = filedialog.askopenfilename(title="Open InfoIC2Plus.dll", filetypes=[("DLL", "*.dll"), ("All files", "*.*")])
        if path:
            self._open(path)

    def _open(self, path):
        try:
            self.db = InfoIC2PlusDB(path)
        except Exception as e:
            messagebox.showerror("Failed to open", str(e))
            return
        self.dirty = False
        self.title("InfoIC2Plus.dll Editor - %s" % os.path.basename(path))
        self._refresh_family_list()
        self.status.config(text="Loaded %s (%d families)." % (path, FAMILY_COUNT))

    def _save(self, overwrite):
        if not self.db:
            return
        try:
            out = self.db.save(overwrite=overwrite)
        except Exception as e:
            messagebox.showerror("Save failed", str(e))
            return
        self.dirty = False
        messagebox.showinfo("Saved", "Written to:\n%s" % out)
        self.status.config(text="Saved to %s" % out)

    # --------------------------------------------------------- families --
    def _refresh_family_list(self):
        self.family_list.delete(0, tk.END)
        if not self.db:
            return
        needle = self.family_filter_var.get().lower()
        self._family_index_map = []
        for fi in range(FAMILY_COUNT):
            fam = self.db.get_family(fi)
            label = "%3d  %-18s %-30s (%d)" % (fi, fam["short_name"], fam["display_name"], fam["variant_count"])
            if needle and needle not in fam["short_name"].lower() and needle not in fam["display_name"].lower():
                continue
            self.family_list.insert(tk.END, label)
            self._family_index_map.append(fi)

    def _load_selected_family(self):
        sel = self.family_list.curselection()
        if not sel or not self.db:
            return
        fi = self._family_index_map[sel[0]]
        self._show_family(fi)

    def _show_family(self, fi):
        self.current_family = self.db.get_family(fi)
        self.current_variants = list(enumerate(self.db.get_variants(fi)))
        self.variant_label.config(text="Family %d: %s - %s (%d chips)" % (
            fi, self.current_family["short_name"], self.current_family["display_name"], len(self.current_variants)))
        self._refresh_variant_tree()

    def _refresh_variant_tree(self):
        self.variant_tree.delete(*self.variant_tree.get_children())
        short = self.current_family["short_name"] if self.current_family else ""
        for vi, v in self.current_variants:
            self.variant_tree.insert("", tk.END, iid=str(vi), values=(vi, short + v["name_suffix"]))

    # ---------------------------------------------------------- search --
    def _do_search(self):
        if not self.db:
            return
        text = self.search_var.get().strip()
        if not text:
            return
        hits = self.db.search_variants(text)
        if not hits:
            messagebox.showinfo("Search", "No matches for %r" % text)
            return
        # Show results grouped: just jump to the family of the first hit
        # and pre-select it; list all hits in the tree with family context.
        self.variant_tree.delete(*self.variant_tree.get_children())
        self.current_family = None
        self.current_variants = []
        self._search_hits = hits
        self.variant_label.config(text="Search results for %r (%d hits) - select then Edit/Delete works" % (text, len(hits)))
        for n, (fi, short_name, vi, v) in enumerate(hits):
            self.variant_tree.insert("", tk.END, iid="search-%d" % n, values=("f%d/%d" % (fi, vi), short_name + v["name_suffix"]))

    # ---------------------------------------------------------- select --
    def _resolve_selection(self):
        """Return (family_index, variant_index, variant_dict) for whatever
        is currently selected in the tree, whether from a family view or a
        cross-family search result."""
        sel = self.variant_tree.selection()
        if not sel:
            return None
        iid = sel[0]
        if iid.startswith("search-"):
            n = int(iid.split("-")[1])
            fi, short_name, vi, v = self._search_hits[n]
            return fi, vi, v
        else:
            vi = int(iid)
            if self.current_family is None:
                return None
            for idx, v in self.current_variants:
                if idx == vi:
                    return self.current_family["family_index"], vi, v
        return None

    def _load_selected_variant(self):
        sel = self._resolve_selection()
        if not sel:
            return
        fi, vi, v = sel
        self.form_vars["name_suffix"].set(v["name_suffix"])
        for key in FIELD_KEYS:
            self.form_vars[key].set(str(v[key]))
        self._update_computed_label(v)

    def _update_computed_label(self, v):
        if v.get("page_size") and v.get("pages_per_block"):
            block_size = v["pages_per_block"] * (v["page_size"] + v["spare_size"])
            device_size = v["total_blocks"] * block_size
            self.computed_label.config(text="Computed Block Size: %d bytes\nComputed Device Size: %d bytes" % (block_size, device_size))
        else:
            self.computed_label.config(text="")

    # ------------------------------------------------------------ edit --
    def _read_form_fields(self):
        fields = {"name_suffix": self.form_vars["name_suffix"].get()}
        for key in FIELD_KEYS:
            raw = self.form_vars[key].get().strip()
            if raw == "":
                continue
            try:
                fields[key] = int(raw, 0)
            except ValueError:
                raise ValueError("Field %r has an invalid number: %r" % (key, raw))
        return fields

    def _apply_edit(self):
        sel = self._resolve_selection()
        if not sel or not self.db:
            messagebox.showwarning("No selection", "Select a chip in the list first.")
            return
        fi, vi, _ = sel
        try:
            fields = self._read_form_fields()
            v = self.db.edit_variant(fi, vi, **fields)
        except Exception as e:
            messagebox.showerror("Edit failed", str(e))
            return
        self.dirty = True
        self._update_computed_label(v)
        if self.current_family and self.current_family["family_index"] == fi:
            self._show_family(fi)
        self.status.config(text="Edited family %d / variant %d. Not saved to disk yet - use File > Save." % (fi, vi))

    def _delete_selected(self):
        sel = self._resolve_selection()
        if not sel or not self.db:
            messagebox.showwarning("No selection", "Select a chip in the list first.")
            return
        fi, vi, v = sel
        fam = self.db.get_family(fi)
        if not messagebox.askyesno("Confirm delete", "Delete %s%s ?" % (fam["short_name"], v["name_suffix"])):
            return
        self.db.delete_variant(fi, vi)
        self.dirty = True
        if self.current_family and self.current_family["family_index"] == fi:
            self._show_family(fi)
        self.status.config(text="Deleted from family %d. Not saved to disk yet - use File > Save." % fi)

    def _clone_selected(self):
        sel = self._resolve_selection()
        if not sel or not self.db:
            messagebox.showwarning("No selection", "Select a chip to clone first.")
            return
        fi, vi, v = sel
        fam = self.db.get_family(fi)
        new_name = tk.simpledialog_result = _ask_string(
            self, "Clone as new chip",
            "New name suffix (after '%s'), max %d chars:" % (fam["short_name"], NAME_MAX_BYTES - 1))
        if not new_name:
            return
        try:
            self.db.add_variant_cloned(fi, vi, new_name)
        except Exception as e:
            messagebox.showerror("Add failed", str(e))
            return
        self.dirty = True
        if self.current_family and self.current_family["family_index"] == fi:
            self._show_family(fi)
        self.status.config(text="Cloned '%s' -> '%s%s' in family %d. Not saved to disk yet - use File > Save." % (
            v["name_suffix"], fam["short_name"], new_name, fi))


def _ask_string(parent, title, prompt):
    from tkinter import simpledialog
    return simpledialog.askstring(title, prompt, parent=parent)


def main(argv):
    initial = argv[1] if len(argv) > 1 else None
    app = App(initial)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
