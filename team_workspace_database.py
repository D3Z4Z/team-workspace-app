import hashlib
import hmac
import secrets
import sqlite3
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText


database_path = Path(__file__).resolve().with_name("workspace_users.db")
roles = ["admin", "editor", "viewer"]
features = {
    "view_file": roles,
    "create_file": ["admin", "editor"],
    "edit_file": ["admin", "editor"],
    "delete_file": ["admin"],
    "manage_users": ["admin"],
    "view_notifications": roles
}


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600000)


def get_permissions(role):
    return [action for action in features if role in features[action]]


def check_access(user, action):
    if user is None:
        return False
    L = user["logged_in"]
    R = user["role"] in features[action]
    P = action in user["permissions"]
    return L and R and P


class Workspace:
    def __init__(self, path):
        self.database = sqlite3.connect(path)
        self.user = None
        self.attempts = 0
        try:
            with self.database:
                self.database.execute(
                    "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, "
                    "password_hash BLOB NOT NULL, salt BLOB NOT NULL, "
                    "role TEXT NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')))"
                )
                documents_exist = self.database.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'documents'"
                ).fetchone()
                self.database.execute(
                    "CREATE TABLE IF NOT EXISTS documents (file_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "file_name TEXT NOT NULL, content TEXT NOT NULL, last_updated_by TEXT NOT NULL)"
                )
                self.database.execute(
                    "CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "message TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
                )
                if not documents_exist:
                    self.database.executemany(
                        "INSERT INTO documents VALUES (?, ?, ?, ?)",
                        [(101, "ProjectPlan.txt", "Initial project outline", "admin01"),
                         (102, "TeamTasks.txt", "Initial task assignments", "editor01")]
                    )
        except sqlite3.Error:
            self.database.close()
            raise

    def needs_setup(self):
        return self.database.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

    def require(self, action):
        if not check_access(self.user, action):
            raise ValueError("Access denied. Your role or permissions do not allow this action.")

    def add_user(self, username, password, confirmation, role):
        if not self.needs_setup():
            self.require("manage_users")
        elif role != "admin":
            raise ValueError("The first account must be an Admin.")
        username = username.strip()
        if not username:
            raise ValueError("Enter a username.")
        if role not in roles:
            raise ValueError("Choose admin, editor, or viewer.")
        if len(password) < 8 or not password.strip():
            raise ValueError("Use a password with at least 8 characters.")
        if password != confirmation:
            raise ValueError("Passwords do not match.")
        salt = secrets.token_bytes(16)
        try:
            with self.database:
                self.database.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?)",
                    (username, hash_password(password, salt), salt, role)
                )
        except sqlite3.IntegrityError:
            raise ValueError("That username already exists.") from None

    def login(self, username, password):
        if self.attempts >= 3:
            raise ValueError("Three attempts used. Choose Try again to start a new login process.")
        account = self.database.execute(
            "SELECT username, password_hash, salt, role FROM users WHERE username = ?",
            (username.strip(),)
        ).fetchone()
        if account and hmac.compare_digest(hash_password(password, account[2]), account[1]):
            self.user = {"username": account[0], "role": account[3], "logged_in": True,
                         "permissions": get_permissions(account[3])}
            self.attempts = 0
            return
        self.attempts += 1
        raise ValueError("Incorrect credentials. Attempt " + str(self.attempts) + " of 3.")

    def logout(self):
        if self.user:
            self.user["logged_in"] = False
        self.user = None
        self.attempts = 0

    def documents(self):
        self.require("view_file")
        return self.database.execute("SELECT * FROM documents ORDER BY file_id").fetchall()

    def save_document(self, file_id, name, content):
        self.require("create_file" if file_id is None else "edit_file")
        name = name.strip()
        if not name:
            raise ValueError("Enter a document name.")
        if not content.strip():
            raise ValueError("Enter some document content before saving.")
        with self.database:
            if file_id is None:
                cursor = self.database.execute(
                    "INSERT INTO documents (file_name, content, last_updated_by) VALUES (?, ?, ?)",
                    (name, content, self.user["username"])
                )
                file_id = cursor.lastrowid
                action = "created"
            else:
                cursor = self.database.execute(
                    "UPDATE documents SET file_name = ?, content = ?, last_updated_by = ? WHERE file_id = ?",
                    (name, content, self.user["username"], file_id)
                )
                if cursor.rowcount != 1:
                    raise ValueError("Document no longer exists. Refresh the list.")
                action = "updated"
            self.database.execute(
                "INSERT INTO notifications (message) VALUES (?)",
                (name + " was " + action + " by " + self.user["username"] + ".",)
            )
        return file_id

    def delete_document(self, file_id):
        self.require("delete_file")
        with self.database:
            document = self.database.execute(
                "SELECT file_name FROM documents WHERE file_id = ?", (file_id,)
            ).fetchone()
            if document is None:
                raise ValueError("Document no longer exists. Refresh the list.")
            self.database.execute("DELETE FROM documents WHERE file_id = ?", (file_id,))
            self.database.execute("INSERT INTO notifications (message) VALUES (?)",
                                  (document[0] + " was deleted by " + self.user["username"] + ".",))

    def notifications(self):
        self.require("view_notifications")
        return self.database.execute(
            "SELECT created_at, message FROM notifications ORDER BY id DESC"
        ).fetchall()

    def accounts(self):
        self.require("manage_users")
        return self.database.execute("SELECT username, role FROM users ORDER BY username").fetchall()

    def change_role(self, username, role):
        self.require("manage_users")
        if username == self.user["username"]:
            raise ValueError("You cannot change your own role in this simulation.")
        if role not in roles:
            raise ValueError("Choose admin, editor, or viewer.")
        with self.database:
            cursor = self.database.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            if cursor.rowcount != 1:
                raise ValueError("User not found.")


class WorkspaceApp:
    def __init__(self, root, workspace):
        self.root = root
        self.workspace = workspace
        self.current_id = None
        self.dirty = False
        root.title("Team Collaboration Workspace")
        root.geometry("900x610")
        root.minsize(760, 520)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        self.frame = ttk.Frame(root, padding=20)
        self.frame.pack(fill="both", expand=True)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.report_callback_exception = self.callback_error
        self.show_login()

    def callback_error(self, kind, error, traceback):
        messagebox.showerror("Workspace", str(error), parent=self.root)

    def clear(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear()
        self.dirty = False
        setup = self.workspace.needs_setup()
        box = ttk.Frame(self.frame, padding=28)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(box, text="Team Workspace", style="Title.TLabel").pack(anchor="w")
        ttk.Label(box, text="Create your first Admin account" if setup else "Sign in to your workspace").pack(anchor="w", pady=(5, 18))
        ttk.Label(box, text="Username").pack(anchor="w")
        username = ttk.Entry(box, width=36)
        username.pack(fill="x", pady=(3, 10))
        ttk.Label(box, text="Password").pack(anchor="w")
        password = ttk.Entry(box, show="*", width=36)
        password.pack(fill="x", pady=(3, 10))
        confirm = None
        if setup:
            ttk.Label(box, text="Confirm password (at least 8 characters)").pack(anchor="w")
            confirm = ttk.Entry(box, show="*", width=36)
            confirm.pack(fill="x", pady=(3, 10))
        status = ttk.Label(box, text="", wraplength=310)
        status.pack(fill="x", pady=6)

        def submit():
            try:
                if setup:
                    self.workspace.add_user(username.get(), password.get(), confirm.get(), "admin")
                self.workspace.login(username.get(), password.get())
                self.show_workspace()
            except ValueError as error:
                status.config(text=str(error))
                password.delete(0, "end")
                if self.workspace.attempts >= 3:
                    button.config(state="disabled")
                    retry.pack(fill="x", pady=5)

        def reset():
            self.workspace.attempts = 0
            self.show_login()

        button = ttk.Button(box, text="Create Admin and sign in" if setup else "Sign in", command=submit)
        button.pack(fill="x", pady=5)
        retry = ttk.Button(box, text="Try again", command=reset)
        password.bind("<Return>", lambda event: submit() if self.workspace.attempts < 3 else None)
        username.focus_set()

    def show_workspace(self):
        self.clear()
        user = self.workspace.user
        top = ttk.Frame(self.frame)
        top.pack(fill="x", pady=(0, 16))
        ttk.Label(top, text="Team Workspace", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Log out", command=self.logout).pack(side="right")
        ttk.Label(top, text=user["username"] + " | " + user["role"].title()).pack(side="right", padx=15)
        toolbar = ttk.Frame(self.frame)
        toolbar.pack(fill="x", pady=(0, 12))
        for title, command, action in [
            ("New document", self.new_document, "create_file"),
            ("Save", self.save_document, "edit_file"),
            ("Delete", self.delete_document, "delete_file"),
            ("Notifications", self.show_notifications, "view_notifications"),
            ("Manage users", self.manage_users, "manage_users")
        ]:
            ttk.Button(toolbar, text=title, command=command,
                       state="normal" if check_access(user, action) else "disabled").pack(side="left", padx=(0, 7))
        body = ttk.Frame(self.frame)
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body, width=230)
        left.pack(side="left", fill="y", padx=(0, 16))
        ttk.Label(left, text="Documents").pack(anchor="w", pady=(0, 6))
        self.tree = ttk.Treeview(left, columns=("name",), show="headings", selectmode="browse", height=16)
        self.tree.heading("name", text="Name")
        self.tree.column("name", width=220)
        self.tree.pack(side="left", fill="y")
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y")
        self.tree.config(yscrollcommand=scroll.set)
        self.tree.bind("<<TreeviewSelect>>", self.select_document)
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text="Document name").pack(anchor="w")
        self.name = tk.StringVar()
        self.name.trace_add("write", lambda *args: self.mark_dirty())
        self.name_entry = ttk.Entry(right, textvariable=self.name)
        self.name_entry.pack(fill="x", pady=(5, 10))
        self.editor = ScrolledText(right, wrap="word", font=("Segoe UI", 11), relief="solid", borderwidth=1, undo=True)
        self.editor.pack(fill="both", expand=True)
        self.editor.bind("<<Modified>>", self.text_changed)
        self.status = ttk.Label(self.frame, text="Select a document. Changes are saved when you click Save.")
        self.status.pack(fill="x", pady=(12, 0))
        self.refresh_documents()
        self.load_document(None)

    def mark_dirty(self):
        self.dirty = True

    def text_changed(self, event):
        if self.editor.edit_modified():
            self.dirty = True
            self.editor.edit_modified(False)

    def can_leave(self):
        if not self.dirty:
            return True
        answer = messagebox.askyesnocancel("Unsaved changes", "Save your changes before continuing?", parent=self.root)
        if answer is None:
            return False
        return self.save_document() if answer else True

    def refresh_documents(self, selected=None):
        self.records = {str(row[0]): row for row in self.workspace.documents()}
        self.tree.delete(*self.tree.get_children())
        for key, row in self.records.items():
            self.tree.insert("", "end", iid=key, values=(row[1],))
        if selected is not None and str(selected) in self.records:
            self.tree.selection_set(str(selected))

    def load_document(self, file_id):
        row = self.records.get(str(file_id))
        self.current_id = file_id
        self.name.set(row[1] if row else "")
        self.editor.config(state="normal")
        self.editor.delete("1.0", "end")
        if row:
            self.editor.insert("1.0", row[2])
        editable = check_access(self.workspace.user, "edit_file")
        self.editor.config(state="normal" if editable else "disabled")
        self.name_entry.config(state="normal" if editable else "readonly")
        self.editor.edit_modified(False)
        self.dirty = False
        if row:
            self.status.config(text="Document " + str(row[0]) + " | Last updated by " + row[3])

    def select_document(self, event):
        selection = self.tree.selection()
        if not selection or int(selection[0]) == self.current_id:
            return
        target_id = int(selection[0])
        previous_id = self.current_id
        if not self.can_leave():
            self.tree.selection_remove(*self.tree.selection())
            if previous_id is not None:
                self.tree.selection_set(str(previous_id))
            return
        self.load_document(target_id)
        self.tree.selection_set(str(target_id))

    def new_document(self):
        self.workspace.require("create_file")
        if self.can_leave():
            self.tree.selection_remove(*self.tree.selection())
            self.load_document(None)
            self.status.config(text="New document | Enter a name and content, then click Save.")
            self.name_entry.focus_set()

    def save_document(self):
        try:
            file_id = self.workspace.save_document(self.current_id, self.name.get(), self.editor.get("1.0", "end-1c"))
        except (ValueError, sqlite3.Error) as error:
            messagebox.showerror("Cannot save", str(error), parent=self.root)
            return False
        self.current_id = file_id
        self.dirty = False
        self.refresh_documents(file_id)
        self.status.config(text="Saved to database | Document " + str(file_id))
        return True

    def delete_document(self):
        self.workspace.require("delete_file")
        if self.current_id is None:
            messagebox.showinfo("Delete document", "Select a saved document first.", parent=self.root)
            return
        if messagebox.askyesno("Delete document", "Permanently delete this document?", parent=self.root):
            self.workspace.delete_document(self.current_id)
            self.refresh_documents()
            self.load_document(None)
            self.status.config(text="Document deleted and notification saved.")

    def show_notifications(self):
        window = tk.Toplevel(self.root)
        window.title("Notifications")
        window.geometry("620x340")
        text = ScrolledText(window, wrap="word", font=("Segoe UI", 10), padx=12, pady=12)
        text.pack(fill="both", expand=True)
        rows = self.workspace.notifications()
        text.insert("end", "\n\n".join(date + " UTC\n" + message for date, message in rows) if rows else "No notifications yet.")
        text.config(state="disabled")

    def manage_users(self):
        self.workspace.require("manage_users")
        window = tk.Toplevel(self.root)
        window.title("Manage users")
        window.resizable(False, False)
        window.transient(self.root)
        window.grab_set()
        frame = ttk.Frame(window, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Accounts", style="Title.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        accounts = ttk.Treeview(frame, columns=("username", "role"), show="headings", height=5)
        for column in ["username", "role"]:
            accounts.heading(column, text=column.title())
            accounts.column(column, width=170)
        accounts.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        fields = {}
        for row, label in enumerate(["Username", "Password", "Confirm password", "Role"], start=2):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
            if label == "Role":
                widget = ttk.Combobox(frame, values=roles, state="readonly", width=25)
                widget.set("viewer")
            else:
                widget = ttk.Entry(frame, width=28, show="*" if "password" in label.lower() else "")
            widget.grid(row=row, column=1, pady=4)
            fields[label] = widget

        def refresh():
            accounts.delete(*accounts.get_children())
            for username, role in self.workspace.accounts():
                accounts.insert("", "end", values=(username, role))

        def add():
            self.workspace.add_user(fields["Username"].get(), fields["Password"].get(),
                                    fields["Confirm password"].get(), fields["Role"].get())
            fields["Password"].delete(0, "end")
            fields["Confirm password"].delete(0, "end")
            refresh()
            messagebox.showinfo("Accounts", "Account created.", parent=window)

        def change():
            selection = accounts.selection()
            if not selection:
                raise ValueError("Select an account from the list first.")
            username = accounts.item(selection[0], "values")[0]
            self.workspace.change_role(username, fields["Role"].get())
            refresh()
            messagebox.showinfo("Accounts", "Role updated.", parent=window)

        ttk.Button(frame, text="Add account", command=add).grid(row=6, column=0, pady=(12, 0))
        ttk.Button(frame, text="Set selected user's role", command=change).grid(row=6, column=1, pady=(12, 0))
        refresh()

    def logout(self):
        if self.can_leave():
            self.workspace.logout()
            self.show_login()

    def close(self):
        if self.workspace.user and not self.can_leave():
            return
        self.workspace.database.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        workspace = Workspace(database_path)
    except sqlite3.Error as error:
        root.withdraw()
        messagebox.showerror("Database error", str(error), parent=root)
        root.destroy()
        return
    WorkspaceApp(root, workspace)
    root.mainloop()


if __name__ == "__main__":
    main()
