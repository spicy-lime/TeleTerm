package teleterm;

import com.jediterm.terminal.ui.TerminalAction;
import com.jediterm.terminal.ui.TerminalActionPresentation;

import java.awt.event.KeyEvent;
import java.util.List;
import java.util.function.Predicate;

import javax.swing.KeyStroke;


public class TeleTermPythonInterface
{
	public static TeleTermPlugin tool;
	public static TeleTermPanel panel;
	public static TeleTermMenuBuilder menuBuilder;

	public static void setup(TeleTermPlugin t, TeleTermPanel p, TeleTermMenuBuilder m )
	{
		tool = t;
		panel = p;
		menuBuilder = m;
	}
	
	public void addSubmenuAction(String label, List<TerminalAction> menuItems)
	{
		TeleTermFactory.createSubmenu(new TerminalActionPresentation(label, menuBuilder.empty()), menuItems);
	}
	
	public static void addAction(String label, Predicate<KeyEvent> runnable)
	{
		TeleTermFactory.createAction(new TerminalActionPresentation(label, menuBuilder.empty()), runnable);
	}
	
	public static List<KeyStroke> noKeyStroke()
	{
		return menuBuilder.empty();
	}
	
	public static long parseGdbInt(String selection)
	{
		return TeleTermMenuBuilder.parseGdbInt(selection);
	}
	
	public static String getSelectionText()
	{
		return panel.getSelectionText();
	}
	
	public static String getClipboardText()
	{
		return panel.getClipboardString();
	}
	
	public static void logln(String log)
	{
		tool.logln(log);
	}
}
