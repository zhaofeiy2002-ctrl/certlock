"""Exercise read-only convenience controls with native Tk and mocked policy IO."""
import argparse
import os
import sys
import tempfile
import tkinter as tk
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import certlock

parser = argparse.ArgumentParser()
parser.add_argument('--screenshots', type=Path)
args = parser.parse_args()
certs = [dict(thumbprint=('A' if i == 0 else 'B') * 40, description=label,
              disallowed=True, cert_data='') for i, label in enumerate(('测试规则 Alpha', '测试规则 Beta'))]
paths = [dict(guid='{audit-rule}', path=r'C:\Test folder\中文长路径\sample program.exe',
              description='测试路径', unrestricted=True)]

for dark in (False, True):
    root = tk.Tk()
    root.withdraw()
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(certlock, 'detect_dark_mode', return_value=dark))
            read = stack.enter_context(patch.object(certlock, 'reg_list_certs', return_value=certs))
            stack.enter_context(patch.object(certlock, 'reg_list_hashes', return_value=[]))
            stack.enter_context(patch.object(certlock, 'reg_list_paths', return_value=paths))
            stack.enter_context(patch.object(certlock, 'reg_is_policy_active', return_value=False))
            for name in ('reg_add_cert', 'reg_remove_cert', 'reg_add_path_rule', 'reg_remove_path',
                         'reg_add_hash', 'reg_remove_hash', 'apply_template_plan', '_import_to_trusted_publishers'):
                stack.enter_context(patch.object(certlock, name, side_effect=AssertionError('Policy writes forbidden')))
            for name in ('showerror', 'showinfo', 'showwarning'):
                stack.enter_context(patch.object(certlock.messagebox, name))
            confirm = stack.enter_context(patch.object(certlock.messagebox, 'askyesno', return_value=False))
            certlock.load_preset_cert_data()
            app = certlock.CertLockApp(root)
            root.update_idletasks()
            assert len(app.tree.get_children()) == 2
            assert str(app.btn_remove['state']) == 'disabled'

            first = app.tree.get_children()[0]
            app.tree.selection_set(first)
            app._update_selection_actions()
            assert str(app.btn_copy_rule['state']) == 'normal'
            # Avoid overwriting the user's clipboard during GUI checks.
            with patch.object(root, 'clipboard_clear') as clear, patch.object(root, 'clipboard_append') as append:
                app.on_copy_rule()
                clear.assert_called_once()
                append.assert_called_once_with('A' * 40)

            calls = read.call_count
            app.search_var.set('bEtA')
            assert str(app.btn_remove['state']) == 'disabled'
            with patch.object(root, 'clipboard_clear') as clear, patch.object(root, 'clipboard_append'):
                app.on_copy_rule()
                clear.assert_not_called(), 'Pending search must not copy a soon-hidden selection'
            app._filter_rule_items()
            assert len(app.tree.get_children()) == 1
            assert not app.tree.selection()
            assert str(app.btn_remove['state']) == 'disabled'
            assert read.call_count == calls, 'Typing must not reread policy'
            hidden = first
            app.refresh_list()
            assert not app.tree.exists(hidden), 'Detached stale rows leaked after refresh'
            assert len(app._rule_items) == 2
            assert len(app.tree.get_children()) == 1
            assert app.search_var.get() == 'bEtA'
            selected = app.tree.get_children()[0]
            app.tree.selection_set(selected)
            app.refresh_list()
            assert app._selected_rule()[1][0] == 'B' * 40
            app.on_remove()
            assert confirm.call_count == 1, 'Existing removal confirmation must be retained'

            app.search_var.set('not present')
            app._filter_rule_items()
            assert not app.tree.get_children()
            assert app.result_count['text'] == '0 / 2 条'
            app._clear_search()
            assert len(app.tree.get_children()) == 2
            app.search_var.set('aaaa')
            app._filter_rule_items()
            assert app.tree.item(app.tree.get_children()[0], 'values')[0] == 'A' * 40
            app._clear_search()

            app.on_toggle_view()
            row = app.tree.get_children()[0]
            assert row == paths[0]['guid']
            app.tree.selection_set(row)
            app._update_selection_actions()
            with patch.object(root, 'clipboard_clear'), patch.object(root, 'clipboard_append') as append:
                app.on_copy_rule()
                append.assert_called_once_with(paths[0]['path'])
                app.on_copy_rule(include_details=True)
                assert '测试路径' in append.call_args.args[0]
            app.refresh_list()
            assert app.tree.selection() == (paths[0]['guid'],)
            app.on_toggle_view()
            assert not app.tree.selection()

            with tempfile.TemporaryDirectory() as temp, patch.object(certlock.os, 'startfile') as opener:
                with patch.dict(os.environ, {'LOCALAPPDATA': temp}):
                    app.on_open_backup_folder()
                    opener.assert_not_called()
                    assert not (Path(temp) / 'CertLock').exists()
                backup = Path(temp) / 'backup.json'
                app._last_backup_file = str(backup)
                app.on_open_backup_folder()
                opener.assert_called_once_with(temp)
                opener.side_effect = OSError('simulated folder error')
                app.on_open_backup_folder()
                certlock.messagebox.showerror.assert_called()

            app.search_var.set('alpha')
            app._filter_rule_items()
            read.side_effect = certlock.PolicyReadError('simulated denial')
            app.refresh_list()
            assert not app._rule_items
            assert app.result_count['text'] == '读取失败'
            assert app._selected_rule() is None
            assert str(app.btn_remove['state']) == 'disabled'
            app._clear_search()
            assert '读取失败' in str(app.tree.item(app.tree.get_children()[0], 'values'))
            read.side_effect = None
            app.refresh_list()
            assert len(app._rule_items) == 2

            root.deiconify()
            root.attributes('-topmost', True)
            root.lift()
            for width, height in ((820, 700), (760, 640)):
                root.geometry(f'{width}x{height}+40+40')
                root.update()
                print('Layout', width, height, [(str(w), w.winfo_ismapped(), w.winfo_width(), w.winfo_height())
                      for w in (app.search_entry, app.btn_copy_rule, app.btn_remove, app.btn_export,
                                app.btn_restore, app.tree, app.policy_label)])
                print('Status', app.status_label.cget('text'), app.status_label.winfo_reqwidth(),
                      app.policy_label.winfo_reqwidth(), app.status_label.master.winfo_width())
                if args.screenshots:
                    from PIL import ImageGrab
                    args.screenshots.mkdir(parents=True, exist_ok=True)
                    path = args.screenshots / f'{"dark" if dark else "light"}-{width}x{height}.png'
                    if path.exists():
                        raise RuntimeError('Refusing to replace screenshot evidence')
                    ImageGrab.grab(bbox=(root.winfo_rootx(), root.winfo_rooty(),
                                        root.winfo_rootx() + root.winfo_width(),
                                        root.winfo_rooty() + root.winfo_height())).save(path)
                for widget in (app.search_entry, app.btn_copy_rule, app.btn_remove,
                               app.btn_export, app.btn_restore, app.tree, app.policy_label):
                    assert widget.winfo_ismapped(), str(widget)
                    assert widget.winfo_rootx() >= root.winfo_rootx()
                    assert widget.winfo_rootx() + widget.winfo_width() <= root.winfo_rootx() + root.winfo_width()
                    assert widget.winfo_rooty() + widget.winfo_height() <= root.winfo_rooty() + root.winfo_height()
                assert app.tree.winfo_height() >= 100
            print(f'Usability checks passed: {"dark" if dark else "light"}; no policy or clipboard writes')
    finally:
        root.destroy()
