package teleterm;


import com.jediterm.terminal.model.StyleState;
import com.jediterm.terminal.model.TerminalTextBuffer;
import com.jediterm.terminal.ui.TerminalPanel;
import com.jediterm.terminal.ui.settings.SettingsProvider;

public class TeleTermPanel extends TerminalPanel
{

	public TeleTermPanel(SettingsProvider settingsProvider, 
			TerminalTextBuffer terminalTextBuffer, 
			StyleState styleState) 
	{
		super(settingsProvider, terminalTextBuffer, styleState);
	}
	
}