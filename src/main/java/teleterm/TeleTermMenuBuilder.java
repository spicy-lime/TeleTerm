package teleterm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.KeyStroke;

import com.jediterm.terminal.ui.TerminalAction;
import com.jediterm.terminal.ui.TerminalActionPresentation;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class TeleTermMenuBuilder
{
	TeleTermPlugin tool;
	Map<String, Long> activeBases = new HashMap<String, Long>();
	
	public TeleTermMenuBuilder(TeleTermPlugin t)
	{
		tool = t;
	}
	
	public List<KeyStroke> empty()
	{
		return Collections.emptyList();
	}

    public static long parseGdbInt(String input) {
        input = input.trim().replace("_", "").toLowerCase();
        // Hex with 0x
        if (input.startsWith("0x")) 
        {
            return Long.parseUnsignedLong(input.substring(2), 16);
        }

        // Leading 0 = octal (but reject just "0")
        if (input.startsWith("0") && input.length() > 1 && input.chars().allMatch(c -> c >= '0' && c <= '7')) 
        {
            return Long.parseLong(input, 8);
        }

        // Pure hex with letters, no prefix
        if (input.matches("[a-f0-9]+") && input.matches(".*[a-f].*")) 
        {
            return Long.parseUnsignedLong(input, 16);
        }

        // Decimal
        return Long.parseLong(input, 10);
    }

		

	public TeleTermSubmenuAction buildBaseAddrSubmenu(TeleTermPanel panel)
	{
		MemoryBlock[] blocks = tool.getCurrentProgram().getMemory().getBlocks();
		List<TerminalAction> blockSubmenu = new ArrayList<TerminalAction>();

		for (MemoryBlock block : blocks) 
		{
			blockSubmenu.add(
				new TerminalAction(
						new TerminalActionPresentation(block.getName(), empty()), 
						input -> 
						{
							String selection = panel.getSelectionText();
							try
							{
								long base = parseGdbInt(selection);
								activeBases.put(block.getName(), base);
								tool.logln("Changed base of " + block.getName() + " to " + Long.toHexString(base));
							}
							catch(Exception e)
							{
								tool.logln(e.getStackTrace().toString());
								tool.logln("Failed to set base addr of " + block.getName() + " to " + selection);
							}
							return true;
						}));
		}
		TeleTermSubmenuAction menu = new TeleTermSubmenuAction(new TerminalActionPresentation("Set Base Of", empty()), blockSubmenu); 
		return menu;
	}

	public TeleTermSubmenuAction buildGotoSubmenu(TeleTermPanel panel)
	{
		List<TerminalAction> gotoSubmenu = new ArrayList<TerminalAction>();
		for (Map.Entry<String, Long> entry : activeBases.entrySet()) 
		{
			gotoSubmenu.add(
				new TerminalAction(
						new TerminalActionPresentation(entry.getKey(), empty()), 
						input -> 
						{
							String selection = panel.getSelectionText();
							try
							{
								long offset = parseGdbInt(selection) - entry.getValue();
								long ghidraAddr = tool.getCurrentProgram().getMemory().getBlock(entry.getKey()).getStart().getOffset() + offset;
								GoToService goToService = tool.tool.getService(GoToService.class);
								Address target = tool.getCurrentProgram().getAddressFactory().getAddress(Long.toHexString(ghidraAddr));
								if (goToService != null) 
								{
									goToService.goTo(target);
								}
								tool.logln("Jumped to " + entry.getKey() + ":" + Long.toHexString(ghidraAddr));
								
							}
							catch (Exception e)
							{
								tool.logln(e.getStackTrace().toString());
								tool.logln("Failed to jump to " + selection);
							}
							return true;
						}));
		}
		TeleTermSubmenuAction menu = new TeleTermSubmenuAction(new TerminalActionPresentation("Goto Address As", empty()), gotoSubmenu); 
		return menu;
	}

	public TeleTermSubmenuAction buildPasteAddressAsSubmenu(TeleTermPanel panel)
	{
		List<TerminalAction> gotoSubmenu = new ArrayList<TerminalAction>();
		for (Map.Entry<String, Long> entry : activeBases.entrySet()) 
		{
			gotoSubmenu.add(
				new TerminalAction(
						new TerminalActionPresentation(entry.getKey(), empty()), 
						input -> 
						{
							long addr = Long.parseLong(panel.getClipboardString(), 16);
							try
							{

								long offset = addr - tool.getCurrentProgram().getMemory().getBlock(entry.getKey()).getStart().getOffset();
								long termAddr = entry.getValue() + offset;
								panel.sendString("0x" + Long.toHexString(termAddr));
								
							}
							catch (Exception e)
							{
								tool.logln(e.getStackTrace().toString());
								tool.logln("Failed to paste " + Long.toHexString(addr));
							}
							return true;
						}));
		}
	
		TeleTermSubmenuAction menu = new TeleTermSubmenuAction(new TerminalActionPresentation("Paste Address As", empty()), gotoSubmenu); 
		
		return menu;
	}


}
