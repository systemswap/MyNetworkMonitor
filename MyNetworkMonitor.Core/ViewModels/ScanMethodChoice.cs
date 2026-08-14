using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Scanning.Engine;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Ein Verfahren in der Schublade: angehakt oder nicht, und ob es unter den
    /// aktuellen Bedingungen ueberhaupt laufen kann.
    /// <para>
    /// <see cref="Availability"/> wird bei jeder Aenderung der Bereichsauswahl
    /// neu bestimmt. Ein Verfahren, das nicht laufen kann, wird ausgegraut und
    /// traegt <see cref="BlockReason"/> als Erklaerung - statt still zu
    /// scheitern, wenn man auf Start drueckt.
    /// </para>
    /// </summary>
    public partial class ScanMethodChoice : ObservableObject
    {
        public required IScanMethod Method { get; init; }

        public string Id => Method.Id;
        public string DisplayName => Method.DisplayName;
        public ScanPhase Phase => Method.Phase;
        public FamilySupport Families => Method.Families;
        public bool IsPassive => Method.IsPassive;

        [ObservableProperty] private bool _isSelected;

        /// <summary>
        /// Dieses Verfahren soll nur die Geraete abfragen, die schon in der
        /// Tabelle stehen.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// Das Verfahren geht eine Zielliste durch und laesst sich darum
        /// ueberhaupt beschraenken. Fuer SSDP, mDNS und die ARP-Tabelle gibt es
        /// nichts zu kuerzen - sie bekommen kein Kaestchen.
        /// </summary>
        public bool CanRestrictToKnown => Method.EnumeratesTargets;

        [ObservableProperty] private ScanMethodAvailability _availability = ScanMethodAvailability.Available;

        /// <summary>
        /// Kann angehakt werden. Nur eine harte Sperre nimmt das Kaestchen weg -
        /// fehlende Adminrechte, kein Adapter, kein Raw-Socket. "Kein passendes
        /// Ziel" (<see cref="ScanMethodState.NotApplicable"/>) sperrt dagegen
        /// nicht mehr: das haengt am gewaehlten Bereich, und ohne einen Bereich
        /// muss man die Verfahren trotzdem einstellen koennen - etwa um ein
        /// einzelnes Geraet aus der Tabelle erneut zu scannen. Ob ein Verfahren
        /// dann tatsaechlich laeuft, entscheidet der Lauf gegen seine eigenen
        /// Ziele, nicht dieses Kaestchen.
        /// </summary>
        public bool IsEnabled => Availability.State != ScanMethodState.Blocked;

        /// <summary>Leer, wenn das Verfahren laeuft.</summary>
        public string BlockReason => Availability.CanRun ? string.Empty : Availability.Reason;

        /// <summary>Was das Verfahren findet und wofuer man es benutzt.</summary>
        public string Explanation => Method.Explanation;

        /// <summary>
        /// Was im Tooltip steht: immer die Erklaerung, und darunter der Grund,
        /// falls das Verfahren gerade nicht laufen kann.
        /// <para>
        /// Beides gehoert zusammen. Bisher stand dort nur der Sperrgrund - bei
        /// den lauffaehigen Verfahren also nichts, und das sind die, bei denen
        /// die Frage "soll ich den Haken setzen?" ueberhaupt erst aufkommt.
        /// Umgekehrt hilft einem Gesperrten die blosse Erklaerung nicht weiter,
        /// wenn nirgends steht, warum es ausgegraut ist.
        /// </para>
        /// </summary>
        public string Hint
        {
            get
            {
                if (BlockReason.Length == 0) return Explanation;

                // Zwei verschiedene Lagen: hart gesperrt (Kaestchen weg) oder
                // nur "passt gerade nicht" (Kaestchen bleibt, laeuft aber nicht,
                // solange es so eingestellt ist).
                string lead = Availability.State == ScanMethodState.Blocked
                    ? "Not available right now:"
                    : "Won't run as things are set:";

                return $"{Explanation}\n\n{lead} {BlockReason}";
            }
        }

        /// <summary>Nur IPv6 - traegt in der Oberflaeche die Indigo-Kennzeichnung.</summary>
        public bool IsIpv6Only => Families == FamilySupport.IPv6;

        /// <summary>Steht eingerueckt unter dem Verfahren darueber - siehe <see cref="IScanMethod.Indented"/>.</summary>
        public bool Indented => Method.Indented;

        /// <summary>Kann beide Familien - selten, aber sichtbar zu machen.</summary>
        public bool IsDualStack => Families == FamilySupport.Both;

        // ------------------------------------------------------- Fortschritt

        /// <summary>Wie viele Anfragen dieses Verfahren abgeschickt hat.</summary>
        [ObservableProperty] private int _sent;

        /// <summary>Wie viele Ziele geantwortet haben.</summary>
        [ObservableProperty] private int _responded;

        /// <summary>Wie viele Ziele es insgesamt sind.</summary>
        [ObservableProperty] private int _total;

        /// <summary>Das Verfahren hat in diesem Lauf schon gemeldet.</summary>
        [ObservableProperty] private bool _hasProgress;

        /// <summary>
        /// Die drei Zahlen nebeneinander: gesendet, geantwortet, gesamt.
        /// <para>
        /// Zwei Zahlen genuegen nicht. "254 / 254" liest sich wie "fertig",
        /// waehrend in Wahrheit alles abgeschickt ist und noch auf Antworten
        /// gewartet wird; erst die mittlere Zahl sagt, was dabei herauskam.
        /// </para>
        /// </summary>
        public string ProgressText => HasProgress ? $"{Sent} / {Responded} / {Total}" : string.Empty;

        partial void OnSentChanged(int value) => OnPropertyChanged(nameof(ProgressText));
        partial void OnRespondedChanged(int value) => OnPropertyChanged(nameof(ProgressText));
        partial void OnTotalChanged(int value) => OnPropertyChanged(nameof(ProgressText));
        partial void OnHasProgressChanged(bool value) => OnPropertyChanged(nameof(ProgressText));

        /// <summary>Setzt die Zaehler vor einem neuen Lauf zurueck.</summary>
        public void ResetProgress()
        {
            Sent = Responded = Total = 0;
            HasProgress = false;
        }

        /// <summary>
        /// Der Haken gilt <em>und</em> das Verfahren kann gerade laufen. Das
        /// ist es, was ein Lauf tatsaechlich ausfuehrt.
        /// <para>
        /// Getrennt vom Haken, weil beides Verschiedenes bedeutet:
        /// <see cref="IsSelected"/> ist der Wunsch des Nutzers,
        /// <see cref="IsEnabled"/> die Lage im Augenblick. Frueher wurde bei
        /// einer Sperre der Haken selbst geloescht - der Wunsch war damit weg
        /// und kam auch dann nicht wieder, wenn das Verfahren gleich darauf
        /// wieder lauffaehig war. Es genuegte, einen anderen Bereich
        /// anzuwaehlen: die Verfuegbarkeitspruefung lief, ein Verfahren war
        /// darin kurz gesperrt, und die Auswahl war still leer.
        /// </para>
        /// </summary>
        public bool IsEffective => IsSelected && IsEnabled;

        partial void OnAvailabilityChanged(ScanMethodAvailability value)
        {
            OnPropertyChanged(nameof(IsEnabled));
            OnPropertyChanged(nameof(BlockReason));
            OnPropertyChanged(nameof(Hint));
            OnPropertyChanged(nameof(IsEffective));
        }

        partial void OnIsSelectedChanged(bool value) => OnPropertyChanged(nameof(IsEffective));
    }
}
