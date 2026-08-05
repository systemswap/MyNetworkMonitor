using System;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Avalonia-Portierung von ZZZ_EnterpriseUsage.ShowEnterpriseMessage() (WPF).
    /// Verhalten 1:1: OK-Button ist zunaechst deaktiviert und wird per 1-Sekunden-
    /// Timer freigeschaltet (countdown startet wie im Original bei 0); Schliessen
    /// ueber "X" beendet die Anwendung, Klick auf OK schliesst nur das Fenster.
    /// </summary>
    public partial class EnterpriseMessageView : Window
    {
        private int _countdown = 0; // wie im WPF-Original: startet bei 0
        private bool _isClosingFromButton;
        private readonly DispatcherTimer _timer;

        public EnterpriseMessageView()
        {
            InitializeComponent();

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            Closing += OnWindowClosing;
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            _countdown--;
            CloseButton.Content = $"You can click OK in: {_countdown} seconds";

            if (_countdown <= 0)
            {
                CloseButton.Foreground = Brushes.White;
                CloseButton.Content = "OK";
                CloseButton.IsEnabled = true;
                _timer.Stop();
            }
        }

        private void CloseButton_Click(object? sender, RoutedEventArgs e)
        {
            _isClosingFromButton = true;
            Close();
        }

        private void OnWindowClosing(object? sender, WindowClosingEventArgs e)
        {
            // Wie im WPF-Original: Schliessen ueber "X" beendet die ganze Anwendung.
            if (!_isClosingFromButton &&
                global::Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        }
    }
}
