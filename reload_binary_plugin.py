"""
IDA Pro Plugin: Quick Binary Reload
Hotkey: Ctrl+Shift+R
Purpose: Reload the current binary without closing IDA
"""

import ida_kernwin
import ida_loader
import ida_idaapi
import ida_nalt
import ida_auto
import ida_segment
import ida_bytes
import ida_ida
import ida_funcs
import ida_name
import ida_entry
import ida_pro
import idautils
import idc
import os
import subprocess
import sys


class ReloadBinaryHandler(ida_kernwin.action_handler_t):
    """Handler for the reload binary action"""

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        """Execute the reload operation"""
        try:
            # Get current input file path (the original binary, not the IDB)
            input_path = ida_nalt.get_input_file_path()

            if not input_path:
                print("[Reload] Error: Cannot determine input file path")
                ida_kernwin.warning("Cannot determine the input file path!")
                return 0

            if not os.path.exists(input_path):
                print(f"[Reload] Error: File not found: {input_path}")
                ida_kernwin.warning(f"File not found: {input_path}")
                return 0

            print(f"[Reload] Reloading binary from: {input_path}")

            # Confirm with user
            result = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, 
                "This will close IDA and reopen the binary from scratch.\n"
                "Any unsaved changes will be lost.\n\n"
                "Continue?")
            
            if result != ida_kernwin.ASKBTN_YES:
                print("[Reload] Cancelled by user")
                return 1

            # Auto-reload without confirmation
            print("[Reload] Auto-reload enabled - no confirmation needed")

            # Get the IDB path to delete it
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            
            # Get IDA executable path
            ida_exe = sys.executable  # Path to IDA itself
            
            # Delete the old IDB files in a batch script that will run after IDA closes
            if idb_path:
                try:
                    # Get base path for both current IDB and the binary's potential IDB
                    current_idb_base = os.path.splitext(idb_path)[0]
                    binary_idb_base = os.path.splitext(input_path)[0]
                    
                    # Create a batch file to delete IDB and reopen IDA
                    batch_path = current_idb_base + "_reload.bat"
                    with open(batch_path, 'w') as f:
                        f.write('@echo off\n')
                        f.write('timeout /t 1 /nobreak >nul\n')
                        
                        # Delete old IDB files from current location
                        extensions = ['.id0', '.id1', '.id2', '.nam', '.til', '.i64']
                        for ext in extensions:
                            file_to_delete = current_idb_base + ext
                            if os.path.exists(file_to_delete):
                                f.write(f'del /F /Q "{file_to_delete}" 2>nul\n')
                        
                        # Also delete from binary location if different
                        if current_idb_base != binary_idb_base:
                            for ext in extensions:
                                file_to_delete = binary_idb_base + ext
                                f.write(f'del /F /Q "{file_to_delete}" 2>nul\n')
                        
                        # Reopen IDA with auto-analysis flags
                        # -A: Automatic mode (non-interactive)
                        # -c: Disassemble new file (don't load database)
                        # -P+: Apply DWARF debug info automatically
                        f.write(f'start "" "{ida_exe}" -A -c "{input_path}"\n')
                        
                        # Delete the batch file itself
                        f.write(f'del /F /Q "{batch_path}"\n')
                    
                    print(f"[Reload] Created reload script: {batch_path}")
                    
                    # Start the batch file
                    subprocess.Popen([batch_path], shell=True, 
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                    
                    print("[Reload] Closing IDA...")
                    
                    # Close IDA without saving
                    ida_pro.qexit(0)
                    
                except Exception as e:
                    print(f"[Reload] Error creating reload script: {e}")
                    ida_kernwin.warning(f"Failed to create reload script: {e}")
                    return 0
            else:
                print("[Reload] Could not determine IDB path")
                ida_kernwin.warning("Could not determine IDB path")
                return 0

            return 1

        except Exception as e:
            print(f"[Reload] Exception occurred: {str(e)}")
            ida_kernwin.warning(f"Error during reload: {str(e)}")
            return 0

        except Exception as e:
            print(f"[Reload] Exception occurred: {str(e)}")
            ida_kernwin.warning(f"Error during reload: {str(e)}")
            return 0

    def update(self, ctx):
        """Check if action should be enabled"""
        return ida_kernwin.AST_ENABLE_ALWAYS


class ReloadBinaryPlugin(ida_idaapi.plugin_t):
    """IDA Plugin to reload binary with hotkey"""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Reload binary without closing IDA"
    help = "Press Ctrl+Shift+R to reload the current binary"
    wanted_name = "Quick Binary Reload"
    wanted_hotkey = ""  # We'll register the hotkey separately

    def init(self):
        """Initialize the plugin"""
        # Register the action
        action_desc = ida_kernwin.action_desc_t(
            'reload_binary:reload',           # Action name
            'Reload Binary',                  # Action text
            ReloadBinaryHandler(),            # Action handler
            'Ctrl+Shift+R',                   # Hotkey
            'Reload the current binary file',  # Tooltip
            -1                                # Icon (no icon)
        )

        if ida_kernwin.register_action(action_desc):
            print("[Reload Plugin] Registered successfully!")
            print("[Reload Plugin] Use Ctrl+Shift+R to reload binary")
            return ida_idaapi.PLUGIN_KEEP
        else:
            print("[Reload Plugin] Failed to register action")
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        """Called when the plugin is run from menu"""
        pass

    def term(self):
        """Cleanup when plugin is unloaded"""
        ida_kernwin.unregister_action('reload_binary:reload')
        print("[Reload Plugin] Unregistered")


def PLUGIN_ENTRY():
    """Required entry point for IDA plugins"""
    return ReloadBinaryPlugin()
