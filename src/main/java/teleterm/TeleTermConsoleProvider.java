
// If provider is desired, it is recommended to move it to its own file
package teleterm;

import javax.swing.JComponent;
import javax.swing.JPanel;

import com.jediterm.terminal.TtyConnector;
import com.jediterm.terminal.ui.JediTermWidget;
import com.jediterm.pty.PtyProcessTtyConnector;
import com.jediterm.terminal.CursorShape;
import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import resources.Icons;

import static com.jediterm.app.PlatformUtilKt.isWindows;

import java.awt.BorderLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


public class TeleTermConsoleProvider extends ComponentProvider 
{

	private JPanel panel;
	private DockingAction action;
	TeleTermWidget widget;

	public TeleTermConsoleProvider(Plugin plugin, String owner) 
	{
		super(plugin.getTool(), "TeleTerm", owner);
		buildPanel();
		createActions();
	}

	public TeleTermWidget createTerminalWidget() 
	{
		CustomSettingsProvider settings = new CustomSettingsProvider();
		TeleTermWidget widget = new TeleTermWidget(80, 24, settings);
		widget.setTtyConnector(createTtyConnector());
		widget.start();
		widget.getTerminalPanel().setDefaultCursorShape(CursorShape.BLINK_BLOCK);
		settings.setTerminalPanel(widget.getTerminalPanel());
		return widget;
	}

	public static TtyConnector createTtyConnector()
	{
		try 
		{
			Map<String, String> envs = System.getenv();
			String[] command;
			if (isWindows()) 
			{
				command = new String[]{"cmd.exe"};
			} 
			else 
			{
				command = new String[]{"/bin/bash"};
				envs = new HashMap<>(System.getenv());
				envs.put("TERM", "xterm-256color");
			}
		
				PtyProcess process = new PtyProcessBuilder().setCommand(command).setEnvironment(envs).start();
				return new PtyProcessTtyConnector(process, StandardCharsets.UTF_8);
		} 
		catch (Exception e) 
		{
			throw new IllegalStateException(e);
		}
	}


	// Customize GUI
	public void buildPanel() {
		panel = new JPanel(new BorderLayout());
		widget = createTerminalWidget();
		panel.add(widget);
		setVisible(true);
	}

	// Customize actions
	public void createActions() 
	{
		action = new DockingAction("My Action", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}