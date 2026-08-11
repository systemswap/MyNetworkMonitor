using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.Models
{
    /// <summary>
    /// Ein Hauptscanner, zu dem sich diese Anlage als Satellit hinausverbindet
    /// - etwa der Arbeitsplatz-Laptop oder der Server.
    /// <para>
    /// Ein Satellit kennt mehrere davon und haelt zu allen gleichzeitig eine
    /// Verbindung, jede fuer sich freigegeben und einzeln wiederverbindend
    /// (SATELLIT.md, Abschnitt 1). Faellt einer aus, arbeitet der andere
    /// weiter.
    /// </para>
    /// <para>
    /// Das Gegenstueck ist <see cref="Satellite"/>: dort steht, wer sich
    /// <em>hierher</em> verbindet.
    /// </para>
    /// </summary>
    public partial class MainScanner : ObservableObject
    {
        /// <summary>
        /// Hostname oder Adresse. Ein Name ist vorzuziehen - er ueberlebt
        /// einen Adresswechsel, und genau das macht einen Laptop als
        /// Hauptscanner moeglich.
        /// </summary>
        [ObservableProperty] private string _host = string.Empty;

        /// <summary>
        /// Die Domaene, an die ein kurzer Name angehaengt wird - optional.
        /// <para>
        /// Gedacht fuer den Fall, dass der Satellit in einem Segment steht, in
        /// dem das Suffix nicht automatisch angehaengt wird: dort loest
        /// "laptop" nicht auf, "laptop.firma.local" schon. Leer lassen, wo der
        /// kurze Name genuegt oder ohnehin eine Adresse eingetragen ist -
        /// darum optional und nicht Pflicht.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _domain = string.Empty;

        /// <summary>
        /// Der Port dieses Empfaengers. Je Eintrag und nicht einmal fuer alle:
        /// derselbe Satellit darf einen Hauptscanner auf 443 und einen anderen
        /// auf 27411 erreichen - das hilft dort, wo nur wenige Ports nach
        /// draussen duerfen.
        /// </summary>
        [ObservableProperty] private int _port = 27411;

        /// <summary>Gedaechtnisstuetze, etwa "Laptop Thomas" oder "Server".</summary>
        [ObservableProperty] private string _note = string.Empty;

        /// <summary>
        /// Ob zu diesem Empfaenger ueberhaupt verbunden werden soll. Aus
        /// heisst: der Eintrag bleibt stehen, wird aber nicht angewaehlt - etwa
        /// der Laptop, waehrend man im Urlaub ist.
        /// </summary>
        [ObservableProperty] private bool _enabled = true;

        /// <summary>
        /// Der gemerkte Fingerabdruck dieses Hauptscanners. Wird beim ersten
        /// Verbinden uebernommen und danach geprueft: ein anderer Schluessel
        /// ist ein anderer Gegenueber, egal wie der Name lautet (SATELLIT.md,
        /// Abschnitt 4, Punkt 5).
        /// <para>
        /// Wird <b>gespeichert</b>. Nur gemerkt gilt er bis zum naechsten
        /// Start, und danach vertraute der Satellit wieder blind dem ersten,
        /// der antwortet - womit die ganze Pruefung nichts wert waere.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _pinnedFingerprint = string.Empty;

        // --- Laufender Zustand, nichts davon wird gespeichert ----------------

        /// <summary>Ob die Verbindung zu diesem Empfaenger gerade steht.</summary>
        [ObservableProperty] private bool _isConnected;

        /// <summary>Ob dieser Empfaenger diese Anlage freigegeben hat.</summary>
        [ObservableProperty] private bool _isApproved;

        /// <summary>Was die Verbindung zuletzt gemeldet hat - ein Satz fuer die Liste.</summary>
        [ObservableProperty] private string _status = "Not connected.";

        /// <summary>Es wird gerade versucht oder gehalten.</summary>
        [ObservableProperty] private bool _isActive;

        /// <summary>
        /// Die Verbindung steht, die Freigabe fehlt noch - der Zustand
        /// zwischen "Connect gedrueckt" und "am Hauptscanner angenommen".
        /// </summary>
        public bool IsWaitingForApproval => IsConnected && !IsApproved;

        partial void OnIsConnectedChanged(bool value) => OnPropertyChanged(nameof(IsWaitingForApproval));
        partial void OnIsApprovedChanged(bool value) => OnPropertyChanged(nameof(IsWaitingForApproval));

        /// <summary>
        /// Der Name, mit dem tatsaechlich verbunden wird: der kurze Name samt
        /// Domaene, wenn eine angegeben ist und noetig ist.
        /// <para>
        /// Angehaengt wird nur, wenn <see cref="Host"/> keinen Punkt und keinen
        /// Doppelpunkt enthaelt. Eine IPv4 traegt Punkte, eine IPv6 Doppelpunkte,
        /// ein bereits vollstaendiger Name Punkte - in allen drei Faellen waere
        /// ein angehaengtes Suffix falsch, und der Eintrag liefe ins Leere.
        /// </para>
        /// </summary>
        public string TargetHost
        {
            get
            {
                string host = Host?.Trim() ?? string.Empty;
                string domain = Domain?.Trim().TrimStart('.') ?? string.Empty;

                if (domain.Length == 0) return host;
                if (host.Length == 0) return host;
                if (host.Contains('.') || host.Contains(':')) return host;

                return $"{host}.{domain}";
            }
        }

        /// <summary>Wie der Eintrag in der Liste steht.</summary>
        public string Display =>
            string.IsNullOrWhiteSpace(Note)
                ? $"{TargetHost}:{Port}"
                : $"{TargetHost}:{Port}  ({Note})";

        partial void OnHostChanged(string value) => OnTargetChanged();
        partial void OnDomainChanged(string value) => OnTargetChanged();
        partial void OnPortChanged(int value) => OnPropertyChanged(nameof(Display));
        partial void OnNoteChanged(string value) => OnPropertyChanged(nameof(Display));

        private void OnTargetChanged()
        {
            OnPropertyChanged(nameof(TargetHost));
            OnPropertyChanged(nameof(Display));
        }
    }
}
