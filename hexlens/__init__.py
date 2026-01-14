import idaapi
import ida_kernwin

class hello_plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Hello plugin example"
    help = ""
    wanted_name = "HexLens"
    wanted_hotkey = "Alt-F8"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        ida_kernwin.info("Hello from IDAPython plugin on macOS!")

    def term(self):
        pass
