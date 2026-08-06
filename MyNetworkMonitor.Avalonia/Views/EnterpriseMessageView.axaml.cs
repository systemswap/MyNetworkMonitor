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
    ///
    /// Verhalten 1:1 zum Original: der OK-Button ist zunaechst deaktiviert und
    /// wird per 1-Sekunden-Timer freigeschaltet (countdown startet wie im
    /// Original bei 0). Erst ein Klick auf OK gibt das Hauptfenster frei; wird
    /// das Fenster auf anderem Weg geschlossen (X, Alt+F4), endet die Anwendung
    /// und das Hauptfenster erscheint gar nicht.
    ///
    /// WPF erreicht das ueber ShowDialog() im Konstruktor des MainWindow - dort
    /// existiert das Hauptfenster noch nicht. In Avalonia wird dieses Fenster
    /// deshalb als Startfenster gezeigt und oeffnet das Hauptfenster erst ueber
    /// <see cref="Accepted"/> (siehe App.axaml.cs).
    /// </summary>
    public partial class EnterpriseMessageView : Window
    {
        /// <summary>
        /// Sekunden, die der OK-Button gesperrt bleibt. Der Timer zaehlt im
        /// Sekundentakt herunter und schaltet bei 0 frei - der Wert ist also
        /// direkt die Wartezeit. (Das WPF-Original startet bei 0 und kommt damit
        /// auf eine Sekunde.)
        /// </summary>
        private const int CountdownSeconds = 3;

        private int _countdown = CountdownSeconds;
        private bool _isClosingFromButton;
        private readonly DispatcherTimer _timer;

        /// <summary>
        /// Wird ausgeloest, wenn der Nutzer OK geklickt hat - und nur dann.
        /// Der Empfaenger oeffnet das Hauptfenster.
        /// </summary>
        public event Action? Accepted;

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

            // Das Hauptfenster wird geoeffnet, BEVOR dieses Fenster schliesst.
            // Sonst waere kurzzeitig kein Fenster offen und die Standard-
            // Abschaltregel (OnLastWindowClose) wuerde die Anwendung beenden.
            Accepted?.Invoke();

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
