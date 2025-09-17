import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, filedialog
import secrets
from vault.db import VaultDB
from vault.crypto import CryptoManager
from vault.generator import PasswordGenerator


class VaultGUI:
    def __init__(self, root, db_path='vault.db'):
        self.root = root
        self.root.title("🔒 Password Vault")
        self.root.configure(bg="#fcefee")  

        self.root.resizable(True, True)
        self.root.minsize(700, 400)

        self._center_window(800, 500)

        self.db = VaultDB(db_path=db_path)
        self.crypto = None
        self.unlocked = False
        self._style_config()
        self._build_widgets()
        self._refresh_list()
        self._startup_unlock_flow()

    def _center_window(self, width, height):
        """Helper to center the main window on screen."""
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = int((screen_w / 2) - (width / 2))
        y = int((screen_h / 2) - (height / 2))
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _style_config(self):
        """Apply cute pink theme styles."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TButton",
                        background="#ffb6c1",
                        foreground="black",
                        padding=6,
                        relief="flat")
        style.map("TButton",
                  background=[("active", "#ff69b4")])

        style.configure("TEntry", padding=4)
        style.configure("Treeview",
                        background="white",
                        fieldbackground="white",
                        foreground="black")
        style.configure("Treeview.Heading", background="#ffb6c1")

    def _build_widgets(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill='x')
        self.search_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.search_var).pack(side='left', fill='x', expand=True, padx=(0, 8))
        ttk.Button(top, text='Search', command=self.on_search).pack(side='left')
        ttk.Button(top, text='Add', command=self.on_add).pack(side='left', padx=4)
        ttk.Button(top, text='Export', command=self.on_export).pack(side='left', padx=4)

        self.tree = ttk.Treeview(self.root, columns=('id', 'site', 'username', 'updated'), show='headings')
        self.tree.heading('id', text='ID')
        self.tree.heading('site', text='Site')
        self.tree.heading('username', text='Username')
        self.tree.heading('updated', text='Updated')
        self.tree.bind('<Double-1>', self.on_double_click)
        self.tree.pack(fill='both', expand=True, padx=8, pady=8)

        bottom = ttk.Frame(self.root, padding=8)
        bottom.pack(fill='x')
        ttk.Button(bottom, text='View', command=self.on_view).pack(side='left')
        ttk.Button(bottom, text='Edit', command=self.on_edit).pack(side='left', padx=4)
        ttk.Button(bottom, text='Delete', command=self.on_delete).pack(side='left', padx=4)
        ttk.Button(bottom, text='Generate PW', command=self.on_generate_pw).pack(side='right')

    def _startup_unlock_flow(self):
        info = self.db.load_master_info()
        if not info:
            pw = simpledialog.askstring('Set master password',
                                        'Create a master password (remember it):',
                                        show='*')
            if not pw:
                messagebox.showerror('Error', 'Master password required')
                self.root.quit()
                return
            salt = secrets.token_bytes(16)
            iterations = 200_000
            crypto = CryptoManager(pw, salt, iterations)
            self.db.store_master_info(salt, crypto.verifier(), iterations)
            self.crypto = crypto
            self.unlocked = True
            messagebox.showinfo('Vault', 'Master password created and vault unlocked')
        else:
            for _ in range(3):
                pw = simpledialog.askstring('Unlock Vault',
                                            'Enter master password:',
                                            show='*')
                if not pw:
                    continue
                crypto = CryptoManager(pw, info['salt'], info['iterations'])
                if crypto.verifier() == info['verifier']:
                    self.crypto = crypto
                    self.unlocked = True
                    messagebox.showinfo('Vault', 'Unlocked')
                    break
            if not self.unlocked:
                messagebox.showerror('Vault', 'Failed to unlock vault')
                self.root.quit()

    def _refresh_list(self, rows=None):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if rows is None:
            rows = self.db.list_all()
        for r in rows:
            self.tree.insert('', 'end',
                             values=(r['id'], r['site'], r['username'] or '', r['updated_at'] or ''))

    def on_search(self):
        t = self.search_var.get().strip()
        rows = self.db.search(t) if t else self.db.list_all()
        self._refresh_list(rows)

    def on_add(self):
        if not self.unlocked:
            messagebox.showerror('Locked', 'Vault locked')
            return
        dialog = AddEditDialog(self.root, title='Add credential')
        if dialog.result:
            site, username, password, notes = dialog.result
            enc = self.crypto.encrypt(password)
            self.db.add_credential(site, username, enc, notes)
            self._refresh_list()

    def on_view(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an entry to view')
            return
        item = self.tree.item(sel[0])
        cred_id = item['values'][0]
        r = self.db.get_credential(cred_id)
        if not r:
            return
        try:
            pwd = self.crypto.decrypt(r['password'])
        except ValueError:
            pwd = '<decryption failed>'
        messagebox.showinfo('Credential',
                            f"Site: {r['site']}\nUser: {r['username']}\nPassword: {pwd}\nNotes: {r['notes']}")

    def on_edit(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an entry to edit')
            return
        item = self.tree.item(sel[0])
        cred_id = item['values'][0]
        r = self.db.get_credential(cred_id)
        if not r:
            return
        try:
            pwd = self.crypto.decrypt(r['password'])
        except ValueError:
            messagebox.showerror('Error', 'Cannot decrypt (wrong key?)')
            return
        dialog = AddEditDialog(self.root, title='Edit credential',
                               initial=(r['site'], r['username'], pwd, r['notes']))
        if dialog.result:
            site, username, password, notes = dialog.result
            enc = self.crypto.encrypt(password)
            self.db.update_credential(cred_id, site, username, enc, notes)
            self._refresh_list()

    def on_delete(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an entry to delete')
            return
        if not messagebox.askyesno('Confirm', 'Delete selected credential?'):
            return
        item = self.tree.item(sel[0])
        cred_id = item['values'][0]
        self.db.delete_credential(cred_id)
        self._refresh_list()

    def on_double_click(self, event):
        self.on_view()

    def on_generate_pw(self):
        gen = PasswordGenerator()
        pw = gen.generate()
        popup = tk.Toplevel(self.root)
        popup.title("Generated Password 💖")
        popup.configure(bg="#ffe4f1")
        self._center_popup(popup, 400, 150)

        tk.Label(popup, text="Your new password:", bg="#ffe4f1").pack(pady=5)

        pw_entry = tk.Entry(popup, width=40, justify="center")
        pw_entry.insert(0, pw)
        pw_entry.config(state="readonly")
        pw_entry.pack(pady=5)

        def copy_pw():
            popup.clipboard_clear()
            popup.clipboard_append(pw)
            popup.update()
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        tk.Button(popup, text="Copy", command=copy_pw, bg="#ff69b4", fg="white").pack(pady=5)
        tk.Button(popup, text="Close", command=popup.destroy, bg="#ddd").pack(pady=5)

    def _center_popup(self, win, width, height):
        screen_w = win.winfo_screenwidth()
        screen_h = win.winfo_screenheight()
        x = int((screen_w / 2) - (width / 2))
        y = int((screen_h / 2) - (height / 2))
        win.geometry(f"{width}x{height}+{x}+{y}")

    def on_export(self):
        if not self.unlocked:
            messagebox.showerror('Locked', 'Vault locked')
            return
        path = filedialog.asksaveasfilename(defaultextension='.vault',
                                            filetypes=[('Vault file', '*.vault')])
        if not path:
            return
        self.db.export_encrypted(self.crypto, path)
        messagebox.showinfo('Export', f'Exported encrypted backup to {path}')


class AddEditDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None, initial=None):
        self.initial = initial
        super().__init__(parent, title=title)

    def body(self, master):
        master.configure(bg="#fcefee")
        ttk.Label(master, text='Site:').grid(row=0, column=0, sticky='w')
        self.site = tk.Entry(master, width=50)
        self.site.grid(row=0, column=1)
        ttk.Label(master, text='Username:').grid(row=1, column=0, sticky='w')
        self.username = tk.Entry(master, width=50)
        self.username.grid(row=1, column=1)
        ttk.Label(master, text='Password:').grid(row=2, column=0, sticky='w')
        self.password = tk.Entry(master, width=50, show="*")
        self.password.grid(row=2, column=1)
        ttk.Label(master, text='Notes:').grid(row=3, column=0, sticky='w')
        self.notes = tk.Text(master, width=38, height=4)
        self.notes.grid(row=3, column=1)
        if self.initial:
            site, username, pwd, notes = self.initial
            self.site.insert(0, site)
            self.username.insert(0, username)
            self.password.insert(0, pwd)
            self.notes.insert('1.0', notes)
        return self.site

    def validate(self):
        if not self.site.get().strip():
            messagebox.showerror('Validation', 'Site is required')
            return False
        if not self.password.get().strip():
            messagebox.showerror('Validation', 'Password is required')
            return False
        return True

    def apply(self):
        self.result = (self.site.get().strip(),
                       self.username.get().strip(),
                       self.password.get().strip(),
                       self.notes.get('1.0', 'end').strip())
