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

import org.jetbrains.annotations.NotNull;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

import teleterm.TeleTermConsoleProvider;
import teleterm.TeleTermStatusProvider;


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

	TeleTermConsoleProvider consoleProvider;
	TeleTermStatusProvider statusProvider;

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
		consoleProvider = new TeleTermConsoleProvider(this, pluginName);
		statusProvider = new TeleTermStatusProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		consoleProvider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() 
	{
		super.init();

		// Acquire services if necessary
	}

	

}
