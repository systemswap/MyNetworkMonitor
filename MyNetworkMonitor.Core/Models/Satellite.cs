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
        /// Die unveraenderliche Kennung, auf die <c>ScanScope.ScannedBy</c>
        /// zeigt. Wird beim Anlegen vergeben und nirgends angezeigt.
        /// <para>
        /// Frueher zeigte ein Bereich auf den <em>Namen</em>. Seit der Satellit
        /// seinen Namen selbst aendern kann, waere das eine Sollbruchstelle:
        /// eine Umbenennung liesse jede Bereichszuordnung ins Leere laufen, und
        /// zwar stillschweigend - der Bereich wuerde einfach nicht mehr
        /// gescannt. Der Fingerabdruck taugt dafuer auch nicht, denn er
        /// wechselt, wenn der Satellit sich einen neuen Schluessel ausstellt.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _id = Guid.NewGuid().ToString("N");

        /// <summary>
        /// Anzeigename. Frei aenderbar - die Zuordnung haengt an
        /// <see cref="Id"/> und nicht hieran.
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

        // --- Wo er steht, aus seiner Begruessung -----------------------------
        //
        // Wird bei jeder Anmeldung ueberschrieben, nicht nur beim ersten Mal:
        // nach einem Neustart oder einer neuen DHCP-Lease stimmt es sonst
        // nicht mehr. Gespeichert wird es trotzdem, damit die Auswahl auch
        // etwas zeigt, solange der Satellit gerade offline ist.

        /// <summary>Sein Rechnername, wie er ihn selbst meldet.</summary>
        [ObservableProperty] private string _siteHostName = string.Empty;

        /// <summary>Seine Domaene. Leer, wenn er keiner angehoert.</summary>
        [ObservableProperty] private string _siteDomain = string.Empty;

        /// <summary>Seine IPv4-Adressen, durch Komma getrennt.</summary>
        [ObservableProperty] private string _siteIpv4 = string.Empty;

        /// <summary>Seine IPv6-Adressen, durch Komma getrennt.</summary>
        [ObservableProperty] private string _siteIpv6 = string.Empty;

        /// <summary>
        /// Das Netz, das ihn am ehesten beschreibt, etwa <c>192.0.2.0/24</c>.
        /// Steht in der Auswahl hinter dem Namen.
        /// </summary>
        [ObservableProperty] private string _siteNetwork = string.Empty;

        /// <summary>Alle seine Netze, durch Komma getrennt - fuer den Tooltip.</summary>
        [ObservableProperty] private string _siteNetworks = string.Empty;

        /// <summary>
        /// Wie er in der Auswahl "Scanned by satellite" steht: Name und Netz.
        /// <para>
        /// Ohne das Netz sieht man beim Zuweisen eines Bereichs nur einen
        /// Namen und muss raten, ob dieser Satellit im richtigen Segment
        /// sitzt.
        /// </para>
        /// </summary>
        public string PickerText =>
            string.IsNullOrWhiteSpace(SiteNetwork) ? Name : $"{Name}  ·  {SiteNetwork}";

        partial void OnNameChanged(string value) => OnPropertyChanged(nameof(PickerText));
        partial void OnSiteNetworkChanged(string value) => OnPropertyChanged(nameof(PickerText));

        // --- Was er scannen soll ---------------------------------------------

        /// <summary>
        /// "Nur Geraete aus der Tabelle" fuer alle Verfahren dieses Satelliten.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// Die Verfahren, die bei diesem Satelliten nur abfragen sollen, was
        /// schon gefunden wurde - je Verfahren einzeln.
        /// <para>
        /// Wird beim Anlegen einmalig aus den Haupteinstellungen uebernommen
        /// und ist danach unabhaengig: was ein Satellit scannen soll, haengt an
        /// seinem Segment, nicht daran, was hier zuletzt eingestellt war. Eine
        /// spaetere Aenderung an den Haupteinstellungen wirkt deshalb
        /// ausdruecklich <em>nicht</em> auf bestehende Satelliten.
        /// </para>
        /// </summary>
        public HashSet<string> OnlyKnownTargetsFor { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Ob der DNS-Quervergleich bei diesem Satelliten nur die Geraete
        /// prueft, die im Lauf geantwortet haben.
        /// <para>
        /// Kein Verfahren, sondern eine Unterfunktion des Namensscans - steht
        /// aber im selben Kasten, weil sie dieselbe Frage beantwortet und
        /// dieselbe Zeit spart. Aus heisst: auch jede alte Zeile der Tabelle
        /// wird geprueft, und genau so findet man Namen, die noch aufloesen,
        /// obwohl das Geraet laengst weg ist.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _crossCheckOnlyKnownTargets = true;

        /// <summary>
        /// Die Verfahren, die dieser Satellit einschraenken soll - fertig fuer
        /// den Auftragstext.
        /// </summary>
        public IEnumerable<string> EffectiveOnlyKnownFor(IEnumerable<string> restrictable) =>
            OnlyKnownTargets ? restrictable : OnlyKnownTargetsFor;

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
