package teleterm;

import com.jediterm.terminal.TerminalColor;
import com.jediterm.terminal.ui.TerminalPanel;
import com.jediterm.terminal.ui.settings.DefaultSettingsProvider;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import org.jetbrains.annotations.NotNull;

public class CustomSettingsProvider extends DefaultSettingsProvider{
    private Font font;
    private TerminalColor backgroundColor;
    private TerminalColor foregroundColor;
    private TeleTermPanel terminalPanel;

    public CustomSettingsProvider() {
        // Try to use a more reliable monospace font that's commonly available
        String[] monospaceFonts = {
            "Consolas",
            "DejaVu Sans Mono",
            "Liberation Mono",
            "Ubuntu Mono",
            "Monospaced"
        };
        
        // Find the first available monospace font
        Font selectedFont = null;
        for (String fontName : monospaceFonts) {
            if (isFontAvailable(fontName)) {
                selectedFont = new Font(fontName, Font.PLAIN, 12);
                break;
            }
        }
        
        // Fallback to system default monospace if none found
        if (selectedFont == null) {
            selectedFont = new Font("Monospaced", Font.PLAIN, 12);
        }
        
        this.font = selectedFont;
        this.backgroundColor = TerminalColor.BLACK;
        this.foregroundColor = TerminalColor.WHITE;
    }

    private boolean isFontAvailable(String fontName) {
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        String[] fontNames = ge.getAvailableFontFamilyNames();
        for (String name : fontNames) {
            if (name.equals(fontName)) {
                return true;
            }
        }
        return false;
    }

    public void setTerminalPanel(TerminalPanel panel) {
        this.terminalPanel = (TeleTermPanel) panel;
        // Apply current font settings to the panel
        if (panel != null) {
            panel.setFont(font);
            panel.repaint();
        }
    }

    public void setFont(Font font) {
        this.font = font;
        if (terminalPanel != null) {
            terminalPanel.setFont(font);
            terminalPanel.repaint();
            // Force a complete redraw
            terminalPanel.invalidate();
            terminalPanel.validate();
        }
    }

    @Override
    public Font getTerminalFont() {
        return font;
    }

    @Override
    public TerminalColor getDefaultBackground() {
        return backgroundColor;
    }

    @Override
    public TerminalColor getDefaultForeground() {
        return foregroundColor;
    }

    @Override
    public float getLineSpacing() {
        return 1.0f;
    }

    @Override
    public boolean useAntialiasing() {
        return true;
    }

    @Override
    public boolean useInverseSelectionColor() {
        return true;
    }
} 