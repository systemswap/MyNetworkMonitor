using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform
{
    /// <summary>
    /// Avalonia-Implementierung von <see cref="IDialogService"/>. Zeigt einfache
    /// modale Dialoge asynchron über dem aktuellen Hauptfenster an – die
    /// plattformspezifische Entsprechung zur WPF-MessageBox.
    /// </summary>
    public sealed class AvaloniaDialogService : IDialogService
    {
        public Task ShowInfoAsync(string message, string title = "Information")
            => ShowMessageAsync(message, title, confirm: false);

        public Task ShowErrorAsync(string message, string title = "Fehler")
            => ShowMessageAsync(message, title, confirm: false);

        public async Task<bool> ConfirmAsync(string message, string title = "Bestätigen")
            => await ShowMessageAsync(message, title, confirm: true);

        private static async Task<bool> ShowMessageAsync(string message, string title, bool confirm)
        {
            var result = false;

            var buttons = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Spacing = 8,
                Margin = new global::Avalonia.Thickness(0, 16, 0, 0)
            };

            var dialog = new Window
            {
                Title = title,
                Width = 420,
                SizeToContent = SizeToContent.Height,
                CanResize = false,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            };

            if (confirm)
            {
                var yes = new Button { Content = "Ja", MinWidth = 80, IsDefault = true };
                var no = new Button { Content = "Nein", MinWidth = 80, IsCancel = true };
                yes.Click += (_, _) => { result = true; dialog.Close(); };
                no.Click += (_, _) => { result = false; dialog.Close(); };
                buttons.Children.Add(yes);
                buttons.Children.Add(no);
            }
            else
            {
                var ok = new Button { Content = "OK", MinWidth = 80, IsDefault = true, IsCancel = true };
                ok.Click += (_, _) => dialog.Close();
                buttons.Children.Add(ok);
            }

            dialog.Content = new StackPanel
            {
                Margin = new global::Avalonia.Thickness(20),
                Children =
                {
                    new TextBlock { Text = message, TextWrapping = global::Avalonia.Media.TextWrapping.Wrap },
                    buttons
                }
            };

            Window? owner = (global::Avalonia.Application.Current?.ApplicationLifetime
                as IClassicDesktopStyleApplicationLifetime)?.MainWindow;

            if (owner != null)
                await dialog.ShowDialog(owner);
            else
                dialog.Show();

            return result;
        }
    }
}
