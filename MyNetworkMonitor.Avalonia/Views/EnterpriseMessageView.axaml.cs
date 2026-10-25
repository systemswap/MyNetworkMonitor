using System;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Notice shown at start in an enterprise network.
    ///
    /// The OK button starts disabled and is enabled by a one-second countdown
    /// timer. Only a click on OK releases the main window; if the window is
    /// closed any other way (X, Alt+F4), the application exits and the main
    /// window never appears.
    ///
    /// This window is therefore shown as the startup window and opens the main
    /// window only through <see cref="Accepted"/> (see App.axaml.cs).
    /// </summary>
    public partial class EnterpriseMessageView : Window
    {
        /// <summary>
        /// Seconds the OK button stays locked. The timer counts down once per
        /// second and enables the button at 0, so the value is the waiting time.
        /// </summary>
        private const int CountdownSeconds = 3;

        private int _countdown = CountdownSeconds;
        private bool _isClosingFromButton;
        private readonly DispatcherTimer _timer;

        /// <summary>
        /// Raised when OK has been clicked, and only then.
        /// The handler opens the main window.
        /// </summary>
        public event Action? Accepted;

        /// <summary>Creates the window and starts the countdown.</summary>
        public EnterpriseMessageView()
        {
            InitializeComponent();

            CloseButton.Content = $"You can click OK in: {_countdown} seconds";

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

            // Opens the main window BEFORE this window closes. Otherwise no
            // window would be open for a moment, and the default shutdown mode
            // (OnLastWindowClose) would exit the application.
            Accepted?.Invoke();

            Close();
        }

        private void OnWindowClosing(object? sender, WindowClosingEventArgs e)
        {
            // Closing with "X" exits the whole application.
            if (!_isClosingFromButton &&
                global::Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        }
    }
}
