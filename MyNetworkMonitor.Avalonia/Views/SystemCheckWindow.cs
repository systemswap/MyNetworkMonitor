// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using MyNetworkMonitor.Core.Services;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Shows which programs of the system are missing (<see cref="SystemRequirements"/>), what they are for and what
    /// happens without them, with the install commands for Debian/Ubuntu and Fedora to copy – the running system first.
    /// Opens at start when something is missing, and from the settings at any time. Installs nothing itself.
    /// </summary>
    public sealed class SystemCheckWindow : Window
    {
        private static readonly IBrush Panel = Brushes.White;
        private static readonly IBrush Line = new SolidColorBrush(Color.Parse("#D3DFE0"));
        private static readonly IBrush Dim = new SolidColorBrush(Color.Parse("#6C8085"));
        private static readonly IBrush Teal = new SolidColorBrush(Color.Parse("#0B7C8B"));
        private static readonly IBrush Warn = new SolidColorBrush(Color.Parse("#B5482F"));

        private readonly ShellViewModel _shell;
        private readonly StackPanel _content = new() { Spacing = 12 };

        /// <summary>Creates the window and runs the check.</summary>
        /// <param name="shell">Where "don't show again" is stored.</param>
        public SystemCheckWindow(ShellViewModel shell)
        {
            _shell = shell;
            Title = "System check";
            Width = 640;
            SizeToContent = SizeToContent.Height;
            MaxHeight = 720;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = new SolidColorBrush(Color.Parse("#F5F7FA"));

            var again = new Button { Content = "Check again" };
            again.Click += (_, _) => Refresh();
            var close = new Button { Content = "Close", IsDefault = true, IsCancel = true };
            close.Click += (_, _) => Close();

            Content = new ScrollViewer
            {
                Content = new StackPanel
                {
                    Margin = new Thickness(20),
                    Spacing = 16,
                    Children =
                    {
                        _content,
                        new StackPanel
                        {
                            Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right,
                            Children = { again, close },
                        },
                    },
                },
            };
            Refresh();
        }

        /// <summary>
        /// Whether the window should open at start: a required program is missing, or an optional one is missing that
        /// has not been dismissed with "Don't show again".
        /// </summary>
        /// <param name="shell">Where "don't show again" is stored.</param>
        /// <param name="results">The result of <see cref="SystemRequirements.Check"/>.</param>
        /// <returns>True if something needs attention.</returns>
        public static bool NeedsAttention(ShellViewModel shell, IReadOnlyList<SystemCheckResult> results) =>
            results.Any(r => !r.Present && (r.Requirement.Required || !shell.IsSystemCheckHidden(r.Requirement.Id)));

        /// <summary>Runs the check again and rebuilds the content (after installing, without restarting).</summary>
        private void Refresh()
        {
            _content.Children.Clear();
            IReadOnlyList<SystemCheckResult> results = SystemRequirements.Check();

            if (results.Count == 0)
            {
                _content.Children.Add(Text("Nothing extra is needed on this system: all lookups use the operating system directly.", 13));
                return;
            }

            List<SystemRequirement> missing = [.. results.Where(r => !r.Present).Select(r => r.Requirement)];
            _content.Children.Add(Text(missing.Count == 0
                ? "Everything MyNetworkMonitor uses is installed."
                : "Some programs that MyNetworkMonitor uses are missing. Install them with the command for your system, then press Check again.", 13));

            foreach (SystemRequirement requirement in missing) _content.Children.Add(MissingItem(requirement));

            if (missing.Count > 0)
            {
                (string Label, string Command)[] commands =
                [
                    ("Debian / Ubuntu", SystemRequirements.DebianCommand(missing)),
                    ("Fedora", SystemRequirements.FedoraCommand(missing)),
                ];
                if (SystemRequirements.CurrentFamily == PackageFamily.Fedora) Array.Reverse(commands);
                foreach ((string label, string command) in commands) _content.Children.Add(CommandLine(label, command));
            }

            foreach (SystemCheckResult found in results.Where(r => r.Present))
                _content.Children.Add(Text($"✓ {found.Requirement.Command} – found", 11.5, Dim));
        }

        private Control MissingItem(SystemRequirement requirement)
        {
            var item = new StackPanel { Spacing = 4 };
            item.Children.Add(new TextBlock
            {
                Text = $"{requirement.Command} – {(requirement.Required ? "needed" : "optional")}",
                FontWeight = FontWeight.SemiBold,
                FontSize = 13,
                Foreground = requirement.Required ? Warn : Teal,
            });
            item.Children.Add(Text(requirement.Purpose, 12));
            item.Children.Add(Text("Without it: " + requirement.WithoutIt, 12, Dim));
            if (!requirement.Required)
            {
                var hide = new CheckBox { Content = "Don't show again at start", IsChecked = _shell.IsSystemCheckHidden(requirement.Id) };
                hide.IsCheckedChanged += (_, _) => _shell.SetSystemCheckHidden(requirement.Id, hide.IsChecked == true);
                item.Children.Add(hide);
            }
            return Box(item);
        }

        private Control CommandLine(string label, string command)
        {
            var box = new TextBox { Text = command, IsReadOnly = true, FontFamily = new FontFamily("monospace"), FontSize = 12 };
            var copy = new Button { Content = "Copy", VerticalAlignment = VerticalAlignment.Center };
            copy.Click += async (_, _) =>
            {
                if (GetTopLevel(this)?.Clipboard is { } clipboard) await clipboard.SetTextAsync(command);
            };
            var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 8 };
            row.Children.Add(box);
            Grid.SetColumn(copy, 1);
            row.Children.Add(copy);
            return new StackPanel { Spacing = 4, Children = { Text(label, 12, Dim), row } };
        }

        private static Border Box(Control child) => new()
        {
            Background = Panel, BorderBrush = Line, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4),
            Padding = new Thickness(14, 10), Child = child,
        };

        private static TextBlock Text(string text, double size, IBrush? foreground = null) => new()
        {
            Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap, Foreground = foreground ?? Brushes.Black,
        };
    }
}
