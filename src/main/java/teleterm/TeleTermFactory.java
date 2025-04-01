package teleterm;

import java.util.ArrayList;
import java.util.List;

import java.awt.event.KeyEvent;
import java.util.function.Predicate;
import java.util.function.Supplier;

import com.jediterm.terminal.ui.TerminalAction;
import com.jediterm.terminal.ui.TerminalActionPresentation;

public class TeleTermFactory
{
	public static List<TerminalAction> actions = new ArrayList<TerminalAction>();
	public static List<TeleTermSubmenuAction> submenus = new ArrayList<TeleTermSubmenuAction>();
	
	public static TerminalAction createAction(TerminalActionPresentation presentation,	Predicate<KeyEvent> runnable)
	{
		TerminalAction action = new TerminalAction(presentation, runnable);
		actions.add(action);
		return action; 
	}

	public static TeleTermSubmenuAction createSubmenu(TerminalActionPresentation presentation,	List<TerminalAction> menuItems)
	{
		TeleTermSubmenuAction submenu = new TeleTermSubmenuAction(presentation, menuItems);
		submenus.add(submenu);
		return submenu; 
	}
	

}
