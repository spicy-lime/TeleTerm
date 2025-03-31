package teleterm;

import java.awt.BorderLayout;
import java.awt.Font;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;

public class TeleTermStatusProvider extends ComponentProvider
{
	public JPanel panel;
	public JTextArea text;
	public DockingAction action;

	public TeleTermStatusProvider(Plugin plugin, String owner)
	{
		super(plugin.getTool(), "TeleTerm Status", owner);
		buildPanel();
	}

	public void buildPanel() {
		panel = new JPanel(new BorderLayout());
		text = new JTextArea();
		text.setEditable(false);
		text.setFont(new Font("Monospaced", Font.PLAIN, 12));
		JScrollPane scroll = new JScrollPane(text);
		panel.add(scroll, BorderLayout.CENTER);
		setVisible(true);
	}
	
	public void append(String str)
	{
		text.append(str);
		text.setCaretPosition(text.getDocument().getLength());
	}

	@Override
	public JComponent getComponent()
	{
		// TODO Auto-generated method stub
		return panel;
	}
	
}