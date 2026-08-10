namespace MyNetworkMonitor.Core.Services
{
    /// <summary>In welchem Zustand der Satellitendienst ist.</summary>
    public enum ServiceState
    {
        /// <summary>Nicht eingerichtet.</summary>
        NotInstalled,

        /// <summary>Eingerichtet, laeuft aber nicht.</summary>
        Stopped,

        /// <summary>Eingerichtet und laeuft.</summary>
        Running,

        /// <summary>Nicht feststellbar - etwa weil die Plattform es nicht kann.</summary>
        Unknown
    }

    /// <summary>Was ueber den Dienst bekannt ist.</summary>
    /// <param name="State">Der Zustand.</param>
    /// <param name="Message">Klartext fuer den Nutzer.</param>
    /// <param name="StartsWithSystem">Er startet beim Hochfahren von selbst.</param>
    public readonly record struct ServiceStatus(ServiceState State, string Message, bool StartsWithSystem)
    {
        public bool IsInstalled => State is ServiceState.Stopped or ServiceState.Running;
        public bool IsRunning => State == ServiceState.Running;
    }

    /// <summary>Ergebnis eines Eingriffs am Dienst.</summary>
    /// <param name="Success">Hat geklappt.</param>
    /// <param name="Message">Klartext fuer den Nutzer - auch im Erfolgsfall.</param>
    public readonly record struct ServiceChangeResult(bool Success, string Message);

    /// <summary>
    /// Einrichten und Steuern des Satellitendienstes.
    /// <para>
    /// Der Satellit soll dauerhaft laufen und nach einem Neustart von selbst
    /// wiederkommen - dafuer genuegt keine gestartete Oberflaeche. Der Dienst
    /// startet dieselbe Anwendung mit <c>--satellite</c>: ohne Fenster, mit
    /// Protokoll in eine Datei (SATELLIT.md, Abschnitt 9).
    /// </para>
    /// <para>
    /// Einrichten und Entfernen brauchen erhoehte Rechte. Die Umsetzung darf
    /// sich dafuer selbst erhoeht neu starten - der Nutzer sieht eine
    /// Rueckfrage des Betriebssystems und sonst nichts.
    /// </para>
    /// </summary>
    public interface IServiceControl
    {
        /// <summary>Ob sich auf dieser Plattform ueberhaupt ein Dienst einrichten laesst.</summary>
        bool IsSupported { get; }

        /// <summary>Ob die Anwendung gerade erhoeht laeuft.</summary>
        bool IsElevated { get; }

        /// <summary>Fragt den Zustand ab.</summary>
        ServiceStatus Read();

        /// <summary>
        /// Richtet den Dienst ein: Autostart, Wiederanlauf nach einem Absturz,
        /// und startet ihn gleich.
        /// </summary>
        /// <param name="executablePath">Die Anwendung, die als Dienst laufen soll.</param>
        ServiceChangeResult Install(string executablePath);

        /// <summary>Haelt den Dienst an und entfernt ihn wieder.</summary>
        ServiceChangeResult Uninstall();

        /// <summary>Startet den eingerichteten Dienst.</summary>
        ServiceChangeResult Start();

        /// <summary>Haelt den laufenden Dienst an, ohne ihn zu entfernen.</summary>
        ServiceChangeResult Stop();
    }

    /// <summary>Wenn keine Umsetzung da ist - meldet schlicht, dass es nicht geht.</summary>
    public sealed class NullServiceControl : IServiceControl
    {
        private const string NotHere = "Setting up a service is not supported on this platform yet.";

        public bool IsSupported => false;
        public bool IsElevated => false;

        public ServiceStatus Read() => new(ServiceState.Unknown, NotHere, false);

        public ServiceChangeResult Install(string executablePath) => new(false, NotHere);
        public ServiceChangeResult Uninstall() => new(false, NotHere);
        public ServiceChangeResult Start() => new(false, NotHere);
        public ServiceChangeResult Stop() => new(false, NotHere);
    }
}
