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
    /// Corrections to the behavior of the Avalonia DataGrid that cannot be
    /// configured through properties.
    /// </summary>
    public static class DataGridBehaviors
    {
        /// <summary>
        /// Keeps the area below the last row free while the horizontal scroll
        /// bar is visible.
        ///
        /// The DataGrid template places this scroll bar over the row area instead
        /// of below it: measured, the row area spans y=32 to y=500 and the scroll
        /// bar y=484 to y=500. The scroll bar therefore covers the last row, which
        /// stays hidden even when scrolled to the end. Only the results table is
        /// affected, because only it has enough columns for a horizontal scroll bar.
        ///
        /// The correction shortens the row area by the height of the scroll bar so
        /// that both are adjacent instead of overlapping.
        /// </summary>
        public static readonly AttachedProperty<bool> ReserveHorizontalScrollBarSpaceProperty =
            AvaloniaProperty.RegisterAttached<DataGrid, bool>(
                "ReserveHorizontalScrollBarSpace", typeof(DataGridBehaviors));

        /// <summary>Sets <see cref="ReserveHorizontalScrollBarSpaceProperty"/> on a grid.</summary>
        public static void SetReserveHorizontalScrollBarSpace(DataGrid grid, bool value)
            => grid.SetValue(ReserveHorizontalScrollBarSpaceProperty, value);

        /// <summary>Gets <see cref="ReserveHorizontalScrollBarSpaceProperty"/> of a grid.</summary>
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

            // Writes only on a real difference; otherwise every layout pass
            // would trigger the next one.
            if (Math.Abs(margin.Bottom - reserved) < 0.5) return;

            presenter.Margin = new Thickness(margin.Left, margin.Top, margin.Right, reserved);
        }
    }
}
