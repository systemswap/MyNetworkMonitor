using System;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.VisualTree;

namespace MyNetworkMonitor.Avalonia.Controls
{
    /// <summary>
    /// Korrekturen am Verhalten von Avalonias DataGrid, die sich nicht ueber
    /// Eigenschaften einstellen lassen.
    /// </summary>
    public static class DataGridBehaviors
    {
        /// <summary>
        /// Haelt den Bereich unter der letzten Zeile frei, solange die
        /// horizontale Bildlaufleiste sichtbar ist.
        ///
        /// Im DataGrid-Template liegt diese Leiste ueber dem Zeilenbereich statt
        /// darunter: gemessen reicht der Zeilenbereich von y=32 bis y=500, die
        /// Leiste von y=484 bis y=500. Die letzte Zeile wird dadurch von ihr
        /// verdeckt - man scrollt ans Ende und sieht sie trotzdem nicht.
        /// Betroffen ist nur die Ergebnistabelle, weil nur sie genug Spalten fuer
        /// eine horizontale Leiste hat.
        ///
        /// Die Korrektur verkuerzt den Zeilenbereich um die Hoehe der Leiste,
        /// sodass beide aneinander grenzen statt sich zu ueberlappen.
        /// </summary>
        public static readonly AttachedProperty<bool> ReserveHorizontalScrollBarSpaceProperty =
            AvaloniaProperty.RegisterAttached<DataGrid, bool>(
                "ReserveHorizontalScrollBarSpace", typeof(DataGridBehaviors));

        public static void SetReserveHorizontalScrollBarSpace(DataGrid grid, bool value)
            => grid.SetValue(ReserveHorizontalScrollBarSpaceProperty, value);

        public static bool GetReserveHorizontalScrollBarSpace(DataGrid grid)
            => grid.GetValue(ReserveHorizontalScrollBarSpaceProperty);

        static DataGridBehaviors()
        {
            ReserveHorizontalScrollBarSpaceProperty.Changed.AddClassHandler<DataGrid>((grid, args) =>
            {
                if (args.NewValue is true) grid.LayoutUpdated += OnLayoutUpdated;
                else grid.LayoutUpdated -= OnLayoutUpdated;
            });
        }

        private static void OnLayoutUpdated(object? sender, EventArgs e)
        {
            if (sender is DataGrid grid) Sync(grid);
        }

        private static void Sync(DataGrid grid)
        {
            ScrollBar? horizontal = grid.GetVisualDescendants().OfType<ScrollBar>()
                                        .FirstOrDefault(s => s.Orientation == Orientation.Horizontal);

            DataGridRowsPresenter? presenter = grid.GetVisualDescendants()
                                                   .OfType<DataGridRowsPresenter>()
                                                   .FirstOrDefault();

            if (horizontal == null || presenter == null) return;

            double reserved = horizontal.IsVisible ? horizontal.Bounds.Height : 0;

            Thickness margin = presenter.Margin;

            // Nur bei echter Abweichung schreiben - sonst stiesse jede
            // Layout-Runde die naechste an.
            if (Math.Abs(margin.Bottom - reserved) < 0.5) return;

            presenter.Margin = new Thickness(margin.Left, margin.Top, margin.Right, reserved);
        }
    }
}
