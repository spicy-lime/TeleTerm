#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


#TODO Add User Code Here

from teleterm.TeleTermPythonInterface import *

from com.jediterm.terminal.ui import TerminalAction;
from com.jediterm.terminal.ui import TerminalActionPresentation;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

def do_text_menu(input):
    selectionAddr = parseGdbInt(panel.getSelectionText())
    logln("Changed base of .text to " + panel.getSelectionText())
    return True

addAction("python!", do_text_menu)

