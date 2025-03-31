package teleterm;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;

public class TeleTermStatusProvider extends ComponentProvider
{
	public JPanel panel;
	public DockingAction action;

	public TeleTermStatusProvider(Plugin plugin, String owner)
	{
		super(plugin.getTool(), "TeleTerm Status", owner);
		buildPanel();
	}

	public void buildPanel() {
		panel = new JPanel(new BorderLayout());
		setVisible(true);
	}

	@Override
	public JComponent getComponent()
	{
		// TODO Auto-generated method stub
		return panel;
	}
	
}