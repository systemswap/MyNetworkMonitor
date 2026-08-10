using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.Models
{
    /// <summary>
    /// Ein Satellit: eine Instanz dieser Anwendung, die als Dienst in einem
    /// anderen Netzsegment laeuft und von dort aus scannt.
    /// <para>
    /// Der Entwurf steht in SATELLIT.md. Wichtig fuer das Verstaendnis dieser
    /// Klasse: <b>der Satellit verbindet sich hierher</b>, nicht umgekehrt.
    /// Darum stehen hier weder Adresse noch Port als Einstellung - beides ist
    /// Beobachtung. Seine Kennung ist der Fingerabdruck seines Schluessels, und
    /// der ueberlebt jeden Adresswechsel.
    /// </para>
    /// <para>
    /// Solange der Satellitenbetrieb nicht gebaut ist, entstehen Eintraege nur
    /// von Hand: man legt den Namen an, den man spaeter vergeben will, und
    /// kann die Bereiche schon darauf zeigen lassen.
    /// </para>
    /// </summary>
    public partial class Satellite : ObservableObject
    {
        /// <summary>
        /// Anzeigename, zugleich der Wert, auf den <c>ScanScope.ScannedBy</c>
        /// zeigt. Eindeutig innerhalb der Liste.
        /// </summary>
        [ObservableProperty] private string _name = string.Empty;

        /// <summary>
        /// Wozu dieser Satellit da ist - reine Gedaechtnisstuetze, etwa
        /// "Schaltschrank IDF2, hinter der Werksfirewall".
        /// </summary>
        [ObservableProperty] private string _note = string.Empty;

        /// <summary>
        /// Fingerabdruck seines Schluessels - seine eigentliche Kennung. Leer,
        /// solange er sich noch nie gemeldet hat.
        /// </summary>
        [ObservableProperty] private string _fingerprint = string.Empty;

        /// <summary>
        /// Vom Nutzer freigegeben. Ohne Freigabe bekommt er keine Auftraege,
        /// auch wenn er verbunden ist - siehe SATELLIT.md, Abschnitt 4.
        /// </summary>
        [ObservableProperty] private bool _approved;

        /// <summary>Wann er sich zuletzt gemeldet hat. Nur Anzeige.</summary>
        [ObservableProperty] private DateTimeOffset? _lastSeen;

        /// <summary>Seine Anwendungsversion, aus der Begruessung. Nur Anzeige.</summary>
        [ObservableProperty] private string _version = string.Empty;

        /// <summary>Sein Betriebssystem, aus der Begruessung. Nur Anzeige.</summary>
        [ObservableProperty] private string _os = string.Empty;

        /// <summary>Von welcher Adresse er sich zuletzt gemeldet hat. Nur Anzeige.</summary>
        [ObservableProperty] private string _remoteAddress = string.Empty;

        /// <summary>
        /// Ob gerade eine Verbindung besteht. Wird nicht gespeichert: nach
        /// einem Neustart ist niemand verbunden, bis er sich wieder meldet.
        /// </summary>
        [ObservableProperty] private bool _isConnected;

        // --- Laufender Auftrag, nichts davon wird gespeichert ----------------

        /// <summary>Kennung des laufenden Auftrags, oder leer.</summary>
        [ObservableProperty] private string _jobId = string.Empty;

        /// <summary>0 bis 100 - damit man sieht, dass er arbeitet.</summary>
        [ObservableProperty] private int _progressPercent;

        /// <summary>Das Verfahren, das gerade laeuft.</summary>
        [ObservableProperty] private string _progressCurrent = string.Empty;

        /// <summary>Was schon fertig ist.</summary>
        [ObservableProperty] private string _progressDone = string.Empty;

        /// <summary>Was noch aussteht.</summary>
        [ObservableProperty] private string _progressPending = string.Empty;

        /// <summary>Es laeuft gerade ein Auftrag.</summary>
        public bool IsBusy => !string.IsNullOrEmpty(JobId);

        partial void OnJobIdChanged(string value)
        {
            OnPropertyChanged(nameof(IsBusy));
            RaiseStatus();
        }

        partial void OnProgressPercentChanged(int value) => OnPropertyChanged(nameof(StatusText));

        /// <summary>
        /// Was mit diesem Eintrag gerade los ist - ein Satz fuer die Liste,
        /// damit man den Zustand nicht aus vier Feldern zusammenreimen muss.
        /// </summary>
        public string StatusText
        {
            get
            {
                if (IsBusy) return $"{ProgressPercent}%  {ProgressCurrent}".TrimEnd();
                if (IsConnected && Approved) return "Connected";
                if (IsConnected) return "Waiting for approval";
                if (string.IsNullOrWhiteSpace(Fingerprint)) return "Never connected";
                if (!Approved) return "Not approved";

                return LastSeen is null
                    ? "Offline"
                    : $"Offline since {LastSeen.Value.LocalDateTime:g}";
            }
        }

        /// <summary>Er hat sich schon einmal gemeldet und traegt eine Kennung.</summary>
        public bool IsKnown => !string.IsNullOrWhiteSpace(Fingerprint);

        /// <summary>Er wartet auf die Freigabe durch den Nutzer.</summary>
        public bool NeedsApproval => IsKnown && !Approved;

        partial void OnIsConnectedChanged(bool value) => RaiseStatus();
        partial void OnApprovedChanged(bool value) => RaiseStatus();
        partial void OnFingerprintChanged(string value) => RaiseStatus();
        partial void OnLastSeenChanged(DateTimeOffset? value) => RaiseStatus();

        private void RaiseStatus()
        {
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(IsKnown));
            OnPropertyChanged(nameof(NeedsApproval));
        }
    }
}
