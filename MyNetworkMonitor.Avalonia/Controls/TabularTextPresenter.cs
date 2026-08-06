using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace MyNetworkMonitor.Avalonia.Controls
{
    /// <summary>
    /// Stellt mehrzeilige, mit Tabulatoren gegliederte Zellwerte spaltenweise
    /// ausgerichtet dar.
    ///
    /// Betroffen sind SNMPInfos ("Serial:\t&lt;Wert&gt;"), detectedServicePorts
    /// ("Dienst\tPort\t(Status)") und LookUpIPs ("IP\t-&gt; Hostname"). Die
    /// Werte kommen mit Leerzeichen-Auffuellung (PadRight) und Tabulatoren aus
    /// der Scan-Logik. WPFs TextBlock hat daraus ueber echte Tabstopps eine
    /// saubere Spaltenoptik gemacht; Avalonias TextBlock kennt keine Tabstopps,
    /// wodurch die Auffuellung in einer Proportionalschrift zu ungleichen
    /// Abstaenden fuehrt.
    ///
    /// Statt an der Schrift zu drehen wird der Text hier in ein Grid mit
    /// Auto-Spalten zerlegt: jede Spalte ist so breit wie ihr laengster Eintrag,
    /// alle Werte stehen damit exakt untereinander - unabhaengig von der Schrift.
    /// </summary>
    public class TabularTextPresenter : Decorator
    {
        /// <summary>Abstand zwischen zwei Spalten.</summary>
        private const double ColumnGap = 12;

        public static readonly StyledProperty<string?> TextProperty =
            AvaloniaProperty.Register<TabularTextPresenter, string?>(nameof(Text));

        public string? Text
        {
            get => GetValue(TextProperty);
            set => SetValue(TextProperty, value);
        }

        static TabularTextPresenter()
        {
            TextProperty.Changed.AddClassHandler<TabularTextPresenter>((presenter, _) => presenter.Rebuild());
        }

        private void Rebuild()
        {
            string text = Text ?? string.Empty;

            if (string.IsNullOrWhiteSpace(text))
            {
                Child = null;
                return;
            }

            List<string[]> rows = text
                .Replace("\r\n", "\n")
                .Split('\n')
                .Where(line => !string.IsNullOrWhiteSpace(line))
                // Die Auffuellung mit Leerzeichen stammt aus der alten
                // Tabstopp-Darstellung und wird hier nicht mehr gebraucht.
                .Select(line => line.Split('\t').Select(cell => cell.Trim()).ToArray())
                .ToList();

            if (rows.Count == 0)
            {
                Child = null;
                return;
            }

            int columnCount = rows.Max(r => r.Length);

            var grid = new Grid { VerticalAlignment = VerticalAlignment.Center };

            for (int c = 0; c < columnCount; c++)
            {
                grid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
            }

            for (int r = 0; r < rows.Count; r++)
            {
                grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));

                for (int c = 0; c < rows[r].Length; c++)
                {
                    if (rows[r][c].Length == 0) continue;

                    var cell = new TextBlock
                    {
                        Text = rows[r][c],
                        VerticalAlignment = VerticalAlignment.Center,
                        // Rechter Abstand nur zwischen Spalten, nicht am Ende
                        Margin = new Thickness(0, 0, c < columnCount - 1 ? ColumnGap : 0, 0)
                    };

                    // Die erste Spalte ist bei SNMP und Diensten die Beschriftung
                    if (c == 0 && columnCount > 1) cell.FontWeight = FontWeight.SemiBold;

                    Grid.SetRow(cell, r);
                    Grid.SetColumn(cell, c);
                    grid.Children.Add(cell);
                }
            }

            Child = grid;
        }
    }
}
