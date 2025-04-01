package teleterm;


import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jetbrains.annotations.NotNull;

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


	@Override
	public List<TerminalAction> getActions() 
	{
		List<TerminalAction> actions = new ArrayList<TerminalAction>(super.getActions());
		actions.addAll(List.of(
            new TerminalAction(mySettingsProvider.getLineUpActionPresentation(), input -> 
            {
              scrollUp();
              return true;
            }).separatorBefore(true)
            ,
            new TerminalAction(mySettingsProvider.getLineDownActionPresentation(), input -> 
            {
              scrollDown();
              return true;
            }),
            menuBuilder.buildBaseAddrSubmenu(this),
            menuBuilder.buildGotoSubmenu(this)
		));
		return actions;
		
	}
}