"""Exercise the preset dialog without policy writes or elevation."""
import sys
import tkinter as tk
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import certlock


def widgets(parent):
    for child in parent.winfo_children():
        yield child
        yield from widgets(child)


root = tk.Tk()
root.withdraw()
try:
    with patch.object(certlock, 'reg_list_certs', return_value=[]), patch.object(
        certlock, 'reg_list_hashes', return_value=[]), patch.object(
        certlock, 'reg_list_paths', return_value=[]), patch.object(
        certlock, 'reg_add_cert', side_effect=AssertionError('Policy writes forbidden')):
        certlock.load_preset_cert_data()
        app = certlock.CertLockApp(root)
        app._configure_template(certlock.build_common_template())
        root.update_idletasks()
        dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
        controls = list(widgets(dialog))
        labels = [str(w.cget('text')) for w in controls if 'text' in w.keys()]
        for required in ('手动指定 WPS', '添加保留程序', '导出勾选的预设', '预览与导入'):
            assert required in labels, required
        checkboxes = [w for w in controls if isinstance(w, certlock.ttk.Checkbutton)]
        assert len(checkboxes) == 6
        for w in controls:
            if isinstance(w, certlock.ttk.Button):
                assert w.winfo_rootx() + w.winfo_width() <= dialog.winfo_rootx() + dialog.winfo_width()
        print('GUI preset controls verified; no policy writes')
finally:
    root.destroy()
