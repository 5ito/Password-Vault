from vault.gui import VaultGUI
import tkinter as tk

if __name__ == '__main__':
    root = tk.Tk()
    app = VaultGUI(root, db_path='vault.db')
    root.mainloop()
