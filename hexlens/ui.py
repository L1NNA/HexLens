# hexlen_ui.py
# Dockable "Hex Len" panel (Cursor-like) + Start Agent button
# Uses PySide6 (IDA 8+), falls back to PyQt5/PySide2 if needed.

import json
import os
import traceback

import idaapi
import ida_funcs
import ida_kernwin

# ---- Qt import compatibility ----
QtWidgets = QtCore = QtGui = None
try:
    from PySide6 import QtWidgets, QtCore, QtGui
except Exception:
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui
    except Exception:
        from PySide2 import QtWidgets, QtCore, QtGui  # type: ignore

import hexlens.extract as hexlen_extract
import hexlens.chat as hexlen_chat


WIDGET_TITLE = "HexLens"
CONFIG_FILENAME = "hexlens_config.json"


def get_config_path():
    """Get the path to the plugin config file in IDA's user directory."""
    try:
        user_dir = ida_kernwin.get_user_idadir()
        config_dir = os.path.join(user_dir, "plugins", "hexlens")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, CONFIG_FILENAME)
    except Exception:
        # Fallback to plugin directory if IDA user dir not available
        plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(plugin_dir, CONFIG_FILENAME)


def load_api_key():
    """Load API key from config file or environment variable."""
    # First check environment variable (highest priority)
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key:
        return env_key
    
    # Then check config file
    config_path = get_config_path()
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                return config.get("openai_api_key", "")
        except Exception:
            pass
    
    return None


def save_api_key(key: str):
    """Save API key to config file."""
    config_path = get_config_path()
    try:
        config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
            except Exception:
                pass
        
        config["openai_api_key"] = key.strip()
        
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        
        # Also set in environment for current session
        os.environ["OPENAI_API_KEY"] = key.strip()
        return True
    except Exception as e:
        return False


class ChatWorker(QtCore.QThread):
    """Background thread worker for running chat queries."""
    progress_msg = QtCore.Signal(str)  # Signal for progress messages
    finished = QtCore.Signal(str)      # Signal for final answer
    error = QtCore.Signal(str)         # Signal for errors
    
    def __init__(self, user_text: str, db_path: str = None):
        super().__init__()
        self.user_text = user_text
        self.db_path = db_path  # Database path obtained from main thread
    
    def run(self):
        """Run chat in background thread."""
        try:
            def chat_cb(msg: str):
                """Callback for chat progress updates."""
                self.progress_msg.emit(msg)
            
            # If we have a db_path, set it in the chat module before running
            if self.db_path:
                # Store the path so chat can use it (bypassing IDA API calls in thread)
                import hexlens.chat as hexlen_chat_module
                hexlen_chat_module._cached_db_path = self.db_path
            
            # Run chat agent (this blocks, but in background thread)
            answer = hexlen_chat.run_chat(self.user_text, ui_cb=chat_cb)
            
            # Clear cached path after use
            import hexlens.chat as hexlen_chat_module
            hexlen_chat_module._cached_db_path = None
            
            self.finished.emit(answer)
        except Exception as e:
            # Clear cached path on error
            import hexlens.chat as hexlen_chat_module
            hexlen_chat_module._cached_db_path = None
            self.error.emit(f"Error during chat: {str(e)}\n{traceback.format_exc()}")


class HexLenDock(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.widget = None
        self.progress = None
        self.log = None
        self.input = None
        self.btn_start = None
        self.btn_send = None
        self.chat_worker = None  # Track current chat worker

    def OnCreate(self, form):
        self.widget = self.FormToPyQtWidget(form)
        self._build_ui(self.widget)
        # Set initial size for chat window (narrow and long)
        if self.widget:
            self.widget.resize(450, 700)

    def OnClose(self, form):
        self.widget = None

    def _build_ui(self, parent):
        layout = QtWidgets.QVBoxLayout(parent)

        header = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("HexLens")
        title.setStyleSheet("font-weight: 600; font-size: 14px;")
        header.addWidget(title)

        self.btn_start = QtWidgets.QPushButton("Start Agent")
        self.btn_start.clicked.connect(self.on_start_agent)
        header.addStretch(1)
        header.addWidget(self.btn_start)

        layout.addLayout(header)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Logs will appear here…")
        layout.addWidget(self.log, 1)

        chat_row = QtWidgets.QHBoxLayout()
        self.input = QtWidgets.QLineEdit()
        self.input.setPlaceholderText("Ask Hex Len… (press Enter to send)")
        self.input.returnPressed.connect(self.on_send)  # Enter key sends message
        chat_row.addWidget(self.input, 1)

        self.btn_send = QtWidgets.QPushButton("Send")
        self.btn_send.clicked.connect(self.on_send)
        chat_row.addWidget(self.btn_send)

        layout.addLayout(chat_row)

    def append_log(self, s: str):
        if not self.log:
            return
        self.log.appendPlainText(s)
        cursor = self.log.textCursor()
        # Compatibility: PySide6/PyQt6 use MoveOperation.End, older versions use End
        try:
            cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
        except AttributeError:
            cursor.movePosition(QtGui.QTextCursor.End)
        self.log.setTextCursor(cursor)

    def set_progress(self, current: int, total: int, msg: str = ""):
        pct = int((current * 100) / total) if total else 0
        if self.progress:
            self.progress.setValue(max(0, min(100, pct)))
        if msg:
            self.append_log(msg)
        QtWidgets.QApplication.processEvents()

    def ensure_api_key(self) -> bool:
        # Try to load from config or environment
        key = load_api_key()
        if key:
            os.environ["OPENAI_API_KEY"] = key
            return True

        # Prompt user for API key
        key, ok = QtWidgets.QInputDialog.getText(
            self.widget,
            "OpenAI API Key Required",
            "Enter OPENAI_API_KEY (will be saved for future sessions):",
            QtWidgets.QLineEdit.Password
        )
        if not ok or not key.strip():
            self.append_log("Start cancelled: no API key provided.")
            return False

        # Save to config file
        if save_api_key(key):
            self.append_log("✅ API key saved to configuration.")
        else:
            self.append_log("⚠️ API key set for this session only (failed to save config).")
            os.environ["OPENAI_API_KEY"] = key.strip()
        
        return True

    def on_start_agent(self):
        if not self.ensure_api_key():
            return

        self.btn_start.setEnabled(False)
        self.progress.setValue(0)
        self.append_log("Starting extraction + indexing…")

        def progress_cb(phase: str, current: int, total: int, msg: str):
            prefix = f"[{phase}] "
            self.set_progress(current, total, prefix + msg)

        try:
            hexlen_extract.run_full_indexing(progress_cb=progress_cb)
            self.append_log("✅ Done.")
            self.progress.setValue(100)
        except Exception as e:
            self.append_log("❌ Error during extraction:")
            self.append_log(str(e))
            self.append_log(traceback.format_exc())
        finally:
            self.btn_start.setEnabled(True)

    def on_send(self):
        text = (self.input.text() or "").strip()
        if not text:
            return
        
        # Cancel any existing chat worker
        if self.chat_worker and self.chat_worker.isRunning():
            self.chat_worker.terminate()
            self.chat_worker.wait()
        
        self.append_log(f"> {text}")
        self.input.setText("")
        
        # Get database path in main thread (IDA API must be called from main thread)
        db_path = None
        try:
            db_path = hexlen_extract._db_path_for_idb()
            # Also try to find it if the expected path doesn't exist
            if not db_path or not os.path.exists(db_path):
                # Try searching in IDB directory
                try:
                    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
                    if idb_path:
                        idb_dir = os.path.dirname(idb_path)
                        if os.path.isdir(idb_dir):
                            for fname in os.listdir(idb_dir):
                                if fname.endswith(hexlen_extract.DB_SUFFIX):
                                    candidate = os.path.join(idb_dir, fname)
                                    if os.path.exists(candidate):
                                        db_path = candidate
                                        break
                except Exception:
                    pass
        except Exception:
            pass
        
        # Disable send button during processing
        self.btn_send.setEnabled(False)
        self.progress.setValue(0)
        
        # Create and start background worker with db_path
        self.chat_worker = ChatWorker(text, db_path=db_path)
        self.chat_worker.progress_msg.connect(self.append_log)
        self.chat_worker.finished.connect(self._on_chat_finished)
        self.chat_worker.error.connect(self._on_chat_error)
        self.chat_worker.start()
    
    def _on_chat_finished(self, answer: str):
        """Handle chat completion."""
        try:
            # Parse and display answer
            try:
                answer_obj = json.loads(answer)
                if "error" in answer_obj:
                    self.append_log(f"❌ Error: {answer_obj['error']}")
                else:
                    # Format answer nicely
                    if "summary" in answer_obj:
                        self.append_log(f"\n📋 {answer_obj['summary']}")
                    
                    # Handle general description
                    if "description" in answer_obj:
                        self.append_log(f"\n{answer_obj['description']}")
                    
                    # Handle characteristics
                    if "characteristics" in answer_obj:
                        chars = answer_obj['characteristics']
                        self.append_log(f"\n📊 Characteristics:")
                        if chars.get("size"):
                            self.append_log(f"   Size: {chars['size']}")
                        if chars.get("complexity"):
                            self.append_log(f"   Complexity: {chars['complexity']}")
                        if chars.get("segment"):
                            self.append_log(f"   Segment: {chars['segment']}")
                        if chars.get("callers"):
                            self.append_log(f"   Callers: {', '.join(chars['callers'][:5])}")
                        if chars.get("callees"):
                            self.append_log(f"   Callees: {', '.join(chars['callees'][:5])}")
                        if chars.get("features"):
                            self.append_log(f"   Features: {', '.join(chars['features'][:8])}")
                    
                    # Handle security notes
                    if "security_notes" in answer_obj and answer_obj['security_notes']:
                        self.append_log(f"\n🔒 Security Notes:")
                        for note in answer_obj['security_notes']:
                            self.append_log(f"   • {note}")
                    
                    # Handle findings (works for both general and security)
                    if "findings" in answer_obj and answer_obj['findings']:
                        self.append_log(f"\n🔍 Findings ({len(answer_obj['findings'])}):")
                        for i, finding in enumerate(answer_obj['findings'], 1):
                            severity = finding.get('severity', '')
                            if severity:
                                self.append_log(f"\n{i}. [{severity.upper()}] {finding.get('type', 'unknown')}")
                            else:
                                self.append_log(f"\n{i}. {finding.get('type', 'observation')}")
                            self.append_log(f"   {finding.get('description', '')}")
                            if finding.get('witness_path'):
                                self.append_log(f"   Path: {' → '.join(finding['witness_path'])}")
                            if finding.get('evidence_refs'):
                                self.append_log(f"   Evidence: {', '.join(finding['evidence_refs'][:3])}")
                            if finding.get('jump_targets'):
                                targets = ', '.join(finding['jump_targets'])
                                self.append_log(f"   Jump to: {targets}")
                                # Make targets clickable (print EA for now; can enhance with buttons later)
                                for target_ea in finding['jump_targets']:
                                    try:
                                        ea_int = int(target_ea, 16) if target_ea.startswith('0x') else int(target_ea)
                                        func_name = ida_funcs.get_func_name(ea_int) or "unknown"
                                        self.append_log(f"      → {target_ea} ({func_name})")
                                    except Exception:
                                        pass
                    
                    if "next_actions" in answer_obj and answer_obj['next_actions']:
                        self.append_log(f"\n➡️  Suggested next actions:")
                        for target in answer_obj['next_actions']:
                            try:
                                ea_int = int(target, 16) if target.startswith('0x') else int(target)
                                func_name = ida_funcs.get_func_name(ea_int) or "unknown"
                                self.append_log(f"   - {target} ({func_name})")
                            except Exception:
                                self.append_log(f"   - {target}")
            except json.JSONDecodeError:
                # Not JSON, display as-is
                self.append_log(f"\n{answer}")
            
            self.progress.setValue(100)
        except Exception as e:
            self.append_log(f"❌ Error during chat: {e}")
            self.append_log(traceback.format_exc())
        finally:
            self.btn_send.setEnabled(True)
            self.chat_worker = None
    
    def _on_chat_error(self, error_msg: str):
        """Handle chat error."""
        self.append_log(f"❌ {error_msg}")
        self.progress.setValue(0)
        self.btn_send.setEnabled(True)
        self.chat_worker = None


class HexLenPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "HexLens dockable panel"
    help = ""
    wanted_name = "HexLens"
    wanted_hotkey = "Alt-F9"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.show_panel()

    def term(self):
        pass

    def show_panel(self):
        # Check if widget already exists
        existing = ida_kernwin.find_widget(WIDGET_TITLE)
        if existing:
            # Widget exists - just bring it to front
            ida_kernwin.activate_widget(existing, True)
            return
        
        # Create new widget as floating window
        self.form = HexLenDock()
        # WOPN_DP_FLOATING makes it a floating window (not docked)
        # If WOPN_DP_FLOATING doesn't exist, try WOPN_DP_TAB or just use 0 for floating
        try:
            options = ida_kernwin.PluginForm.WOPN_DP_FLOATING
        except AttributeError:
            # Fallback: use 0 for floating or try WOPN_DP_TAB
            try:
                options = ida_kernwin.PluginForm.WOPN_DP_TAB
            except AttributeError:
                options = 0  # Default to floating
        
        self.form.Show(WIDGET_TITLE, options=options)


def PLUGIN_ENTRY():
    return HexLenPlugin()
