package teleterm;

import com.jediterm.terminal.TtyConnector;
import com.jediterm.terminal.model.StyleState;
import com.jediterm.terminal.model.TerminalTextBuffer;
import com.jediterm.terminal.ui.JediTermWidget;
import com.jediterm.terminal.ui.TerminalPanel;
import com.jediterm.terminal.ui.settings.SettingsProvider;

public class TeleTermWidget extends JediTermWidget
{
	private TeleTermPanel teleTermPanel;

	public TeleTermWidget(int columns, int lines,
			SettingsProvider settingsProvider)
	{
		super(columns, lines, settingsProvider);
	}

	@Override
	public TeleTermPanel getTerminalPanel()
	{
		return teleTermPanel;
	}

	@Override
	protected TerminalPanel createTerminalPanel(SettingsProvider settingsProvider, 
			 StyleState styleState, 
			 TerminalTextBuffer terminalTextBuffer) 
	{
		teleTermPanel = new TeleTermPanel(settingsProvider, terminalTextBuffer, styleState);
		return teleTermPanel;
	}
}