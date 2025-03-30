/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package teleterm;

import java.awt.BorderLayout;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import org.jetbrains.annotations.NotNull;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import static com.jediterm.app.PlatformUtilKt.isWindows;

import com.jediterm.pty.PtyProcessTtyConnector;
import com.jediterm.terminal.CursorShape;
import com.jediterm.terminal.TtyConnector;
import com.jediterm.terminal.ui.JediTermWidget;
import com.jediterm.terminal.ui.settings.DefaultSettingsProvider;
import com.pty4j.PtyProcess;
import com.pty4j.PtyProcessBuilder;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "TeleTerm description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class TeleTermPlugin extends ProgramPlugin {

	MyProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public TeleTermPlugin(PluginTool tool) 
	{
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		@NotNull String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() 
	{
		super.init();

		// Acquire services if necessary
	}


	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider 
	{

		private JPanel panel;
		private DockingAction action;
		JediTermWidget widget;

		private JediTermWidget createTerminalWidget() 
		{
			CustomSettingsProvider settings = new CustomSettingsProvider();
			TeleTermWidget widget = new TeleTermWidget(80, 24, settings);
			widget.setTtyConnector(createTtyConnector());
			widget.start();
			widget.getTerminalPanel().setDefaultCursorShape(CursorShape.BLINK_BLOCK);
			settings.setTerminalPanel(widget.getTerminalPanel());
			return widget;
		}

		private static TtyConnector createTtyConnector()
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

		public MyProvider(Plugin plugin, String owner) 
		{
			super(plugin.getTool(), "TeleTerm", owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			widget = createTerminalWidget();
			panel.add(widget);
			setVisible(true);
		}

		// Customize actions
		private void createActions() 
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
}
