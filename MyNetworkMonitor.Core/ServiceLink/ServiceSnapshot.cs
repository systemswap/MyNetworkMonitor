namespace MyNetworkMonitor.Core.ServiceLink
{
    /// <summary>
    /// Die Nachrichtenarten zwischen Oberflaeche und Dienst.
    /// <para>
    /// Bewusst dieselbe Huelle wie im Satellitenprotokoll
    /// (<c>SatelliteMessage</c>) und dasselbe Rahmenformat: es gibt keinen
    /// Grund, fuer zwei Meter Datenweg eine zweite Sprache zu erfinden, und was
    /// hier laeuft, laesst sich mit denselben Augen lesen.
    /// </para>
    /// </summary>
    public static class ServiceMessageType
    {
        /// <summary>Oberflaeche fragt: was tust du gerade?</summary>
        public const string Status = "svc.status";

        /// <summary>Dienst antwortet mit einem <see cref="ServiceSnapshot"/> als JSON.</summary>
        public const string StatusReply = "svc.status.reply";

        /// <summary>Oberflaeche: halte den laufenden Auftrag an.</summary>
        public const string StopJob = "svc.stopJob";

        /// <summary>Oberflaeche: lies die Hostliste neu und verbinde neu.</summary>
        public const string Reconnect = "svc.reconnect";

        /// <summary>Dienst: Befehl ausgefuehrt, mit Klartext.</summary>
        public const string Done = "svc.done";
    }

    /// <summary>Wie es einem einzelnen Empfaenger geht, aus Sicht des Dienstes.</summary>
    public sealed class ServiceHostState
    {
        public string Display { get; set; } = string.Empty;
        public bool IsConnected { get; set; }
        public bool IsApproved { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    /// <summary>
    /// Was der Dienst gerade tut - eine Momentaufnahme, wie die Oberflaeche
    /// sie anzeigt.
    /// <para>
    /// Eine Momentaufnahme auf Abruf und kein Strom von Ereignissen: die
    /// Oberflaeche fragt im Sekundentakt nach. Das ist unspektakulaer, aber es
    /// braucht keinen Zustand auf beiden Seiten, ueberlebt jedes Zu- und
    /// Aufmachen des Fensters und kann nicht aus dem Tritt geraten.
    /// </para>
    /// </summary>
    public sealed class ServiceSnapshot
    {
        /// <summary>Unter welchem Namen sich der Dienst meldet.</summary>
        public string OwnName { get; set; } = string.Empty;

        /// <summary>Seine Anwendungsversion.</summary>
        public string Version { get; set; } = string.Empty;

        /// <summary>Fuer welchen Hauptscanner gerade gescannt wird. Leer = keiner.</summary>
        public string JobHost { get; set; } = string.Empty;

        /// <summary>Kennung des laufenden Auftrags.</summary>
        public string JobId { get; set; } = string.Empty;

        /// <summary>0 bis 100.</summary>
        public int JobPercent { get; set; }

        /// <summary>Das Verfahren, das gerade laeuft.</summary>
        public string JobCurrent { get; set; } = string.Empty;

        /// <summary>Was schon fertig ist.</summary>
        public string JobDone { get; set; } = string.Empty;

        /// <summary>Was noch aussteht.</summary>
        public string JobPending { get; set; } = string.Empty;

        /// <summary>Der Zustand je Empfaenger.</summary>
        public List<ServiceHostState> Hosts { get; set; } = [];

        /// <summary>Es laeuft gerade ein Auftrag.</summary>
        public bool IsBusy => !string.IsNullOrEmpty(JobId);
    }

    /// <summary>Wie die Pipe heisst - auf beiden Seiten dieselbe Konstante.</summary>
    public static class ServicePipe
    {
        /// <summary>
        /// Der Name der Pipe.
        /// <para>
        /// Unter Windows wird daraus <c>\\.\pipe\MyNetworkMonitorSatellite</c>,
        /// unter Linux eine Datei im temporaeren Verzeichnis - .NET setzt
        /// benannte Pipes dort auf Unix-Domain-Sockets um. Derselbe Quelltext
        /// traegt also beide Plattformen; nur die Zugriffsrechte werden
        /// verschieden geregelt, siehe die Pipe-Fabrik in PlatformServices.
        /// </para>
        /// </summary>
        public const string Name = "MyNetworkMonitorSatellite";
    }
}
