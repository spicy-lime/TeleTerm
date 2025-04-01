package teleterm;

import java.util.Collections;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import org.jetbrains.annotations.NotNull;

import com.jediterm.terminal.ui.TerminalAction;
import com.jediterm.terminal.ui.TerminalActionPresentation;

public class TeleTermSubmenuAction extends TerminalAction 
{
	private final List<TerminalAction> children;

	public TeleTermSubmenuAction(TerminalActionPresentation presentation, List<TerminalAction> children) 
	{
		super(presentation); // No action on click
		this.children = children;
	}

	public List<TerminalAction> getChildren() 
	{
		return children;
	}

	@Override
	public @NotNull JMenuItem toMenuItem() 
	{
		JMenu submenu = new JMenu(getName());
		for (TerminalAction child : children) 
		{
			submenu.add(child.toMenuItem());
		}
		return submenu;
	}
}