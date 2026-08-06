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

        /// <summary>
        /// Name der Spaltengruppe. Alle Zellen mit demselben Namen teilen sich
        /// ihre Spaltenbreiten, sodass etwa die Ports der erkannten Dienste ueber
        /// alle Tabellenzeilen hinweg an derselben Stelle stehen - auch wenn in
        /// einer Zeile nur "SSH" und in der naechsten "RustdeskServer" steht.
        ///
        /// Ohne das rechnet jede Zelle ihre Breiten fuer sich, weil sie ein
        /// eigenes Grid ist. Voraussetzung: ein Vorfahr traegt
        /// Grid.IsSharedSizeScope (setzt DataTableGridSource am DataGrid).
        /// </summary>
        public static readonly StyledProperty<string?> SharedSizeGroupNameProperty =
            AvaloniaProperty.Register<TabularTextPresenter, string?>(nameof(SharedSizeGroupName));

        public string? Text
        {
            get => GetValue(TextProperty);
            set => SetValue(TextProperty, value);
        }

        public string? SharedSizeGroupName
        {
            get => GetValue(SharedSizeGroupNameProperty);
            set => SetValue(SharedSizeGroupNameProperty, value);
        }

        static TabularTextPresenter()
        {
            TextProperty.Changed.AddClassHandler<TabularTextPresenter>((presenter, _) => presenter.Rebuild());
            SharedSizeGroupNameProperty.Changed.AddClassHandler<TabularTextPresenter>((presenter, _) => presenter.Rebuild());
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

            string? groupName = SharedSizeGroupName;

            for (int c = 0; c < columnCount; c++)
            {
                var definition = new ColumnDefinition(GridLength.Auto);

                // Letzte Spalte bewusst ausgenommen: sie enthaelt den Rest der
                // Zeile und soll nicht alle Zellen auf ihre groesste Breite
                // aufblaehen. Ausgerichtet werden die Spalten davor.
                if (!string.IsNullOrEmpty(groupName) && c < columnCount - 1)
                {
                    definition.SharedSizeGroup = $"{groupName}__{c}";
                }

                grid.ColumnDefinitions.Add(definition);
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
