using System;
using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Shows the license of the program: the file <c>LICENSE</c> that the packages place next to the program.
    /// </summary>
    /// <remarks>
    /// The text is shown inside the program instead of being handed to the system: the file has no extension, and
    /// not every desktop knows which program opens it.
    /// </remarks>
    public sealed class LicenseWindow : Window
    {
        /// <summary>Creates the window and reads the license file.</summary>
        public LicenseWindow()
        {
            Title = "License";
            Width = 860;
            Height = 640;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(Color.Parse("#F5F7FA"));

            var close = new Button { Content = "Close", IsDefault = true, IsCancel = true, HorizontalAlignment = HorizontalAlignment.Right };
            close.Click += (_, _) => Close();

            var text = new TextBox
            {
                Text = ReadLicense(),
                IsReadOnly = true,
                TextWrapping = TextWrapping.NoWrap,
                FontFamily = new FontFamily("monospace"),
                FontSize = 12,
                AcceptsReturn = true,
            };

            var layout = new DockPanel { Margin = new Thickness(16) };
            DockPanel.SetDock(close, Dock.Bottom);
            close.Margin = new Thickness(0, 12, 0, 0);
            layout.Children.Add(close);
            layout.Children.Add(text);
            Content = layout;
        }

        /// <summary>Reads <c>LICENSE</c> next to the program, or explains where to find it.</summary>
        /// <returns>The license text, or a short message when the file is missing or unreadable.</returns>
        private static string ReadLicense()
        {
            string path = Path.Combine(AppContext.BaseDirectory, "LICENSE");
            try
            {
                return File.ReadAllText(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A build started from the IDE has no LICENSE next to it; the packages always do.
                return $"The license file could not be read ({path}: {ex.Message}).\n\n" +
                       "It is the file LICENSE in the source code and in every package of MyNetworkMonitor.";
            }
        }
    }
}
