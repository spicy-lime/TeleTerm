package teleterm;


import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import com.jediterm.terminal.model.StyleState;
import com.jediterm.terminal.model.TerminalTextBuffer;
import com.jediterm.terminal.ui.TerminalPanel;
import com.jediterm.terminal.ui.TerminalAction;
import com.jediterm.terminal.ui.settings.SettingsProvider;

public class TeleTermPanel extends TerminalPanel
{

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
	
	
	@Override
	public void processKeyEvent(final KeyEvent e)
	{
		handleKeyEvent(e);
		e.consume();
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
            }
		)));
		return actions;
		
	}
}