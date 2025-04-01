package teleterm;


import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jetbrains.annotations.NotNull;

import com.jediterm.terminal.TerminalColor;
import com.jediterm.terminal.TextStyle;
import com.jediterm.terminal.model.StyleState;
import com.jediterm.terminal.model.TerminalTextBuffer;
import com.jediterm.terminal.ui.TerminalPanel;
import com.jediterm.terminal.ui.TerminalAction;
import com.jediterm.terminal.ui.TerminalActionPresentation;
import com.jediterm.terminal.ui.settings.SettingsProvider;

import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.script.GhidraScript;

public class TeleTermPanel extends TerminalPanel
{
	List<TerminalAction> teleActions = new ArrayList<TerminalAction>();
	TeleTermMenuBuilder menuBuilder;
	TeleTermStatusProvider statusProvider;

	public TeleTermPanel(SettingsProvider settingsProvider, 
			TerminalTextBuffer terminalTextBuffer, 
			StyleState styleState) 
	{
		super(settingsProvider, terminalTextBuffer, styleState);
		setFocusable(true);
		requestFocusInWindow();
		addKeyListener(new KeyAdapter() {
		    @Override
		    public void keyPressed(KeyEvent e) {
		    	handleKeyEvent(e);
		        e.consume(); 
		    }
		});
	}
	
	public void addAction(TerminalAction action)
	{
		
	}
	
	public void setSubmenuBuilder(TeleTermMenuBuilder builder)
	{
		menuBuilder = builder;
	}
	
	public void setStatusProvider(TeleTermStatusProvider provider)
	{
		
	}

	@Override
	public TextStyle getInversedStyle(@NotNull TextStyle style) {
		return style.toBuilder()
			.setForeground(new TerminalColor(0, 0, 0))        
			.setBackground(new TerminalColor(255, 255, 255))    
			.build();
	}
	
	
	@Override
	public void processKeyEvent(final KeyEvent e)
	{
		handleKeyEvent(e);
		e.consume();
	}

	public @NotNull TerminalActionPresentation getSubmenuPresentation() {
		return new TerminalActionPresentation("Set Base Of", Collections.emptyList());
	}
	
	public List<Object> empty()
	{
		return Collections.emptyList();
	}
	
	public void sendString(String str)
	{
		myTerminalStarter.sendString(str, false);
	}


	@Override
	public List<TerminalAction> getActions() 
	{
		List<TerminalAction> actions = new ArrayList<TerminalAction>(super.getActions());
		actions.addAll(List.of(
            menuBuilder.buildQuickSetText(this).separatorBefore(true),
            menuBuilder.buildBaseAddrSubmenu(this),
            menuBuilder.buildGotoSubmenu(this),
            menuBuilder.buildPasteAddressAsSubmenu(this),
            menuBuilder.buildAutoGotoAddress(this)
		));
		actions.addAll(TeleTermFactory.actions);
		actions.addAll(TeleTermFactory.submenus);
		return actions;
		
	}
}