import idaapi
import ida_kernwin
from hexlens import hello_plugin

def PLUGIN_ENTRY():
    return hello_plugin()
