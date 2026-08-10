using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Persistence;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Die Verwaltung der Scan-Bereiche: Liste links, Maske rechts.
    /// <para>
    /// Arbeitet auf <em>derselben</em> Sammlung wie die Bereichsauswahl im
    /// Kommandobalken. Wer hier einen Bereich anlegt oder umbenennt, sieht das
    /// sofort im Ausklappmenue - eine zweite Liste, die man haendisch abgleicht,
    /// waere die naechste Fehlerquelle.
    /// </para>
    /// <para>
    /// Gespeichert wird in das bisherige <c>ipGroups.xml</c>, damit beide
    /// Oberflaechen waehrend des Umbaus denselben Bestand sehen. Bereiche, die
    /// sich in diesem Format nicht abbilden lassen - der Adapter-Bereich, ein
    /// IPv6-Praefix - werden uebersprungen statt verstuemmelt gespeichert.
    /// </para>
    /// </summary>
    public partial class ScopeEditorViewModel : ObservableObject
    {
        private readonly ObservableCollection<ScanScope> _scopes;
        private string _xmlPath = string.Empty;

        /// <summary>
        /// Sperrt das Speichern waehrend des Ladens. Ohne sie wuerde jeder
        /// hinzugefuegte Bereich die Datei neu schreiben - und der erste
        /// Schreibvorgang aus einer noch halb gefuellten Liste heraus.
        /// </summary>
        private bool _loading;

        public ScopeEditorViewModel(ObservableCollection<ScanScope> scopes)
        {
            _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));

            // Auf jeden Bereich hoeren, nicht nur auf den in der Maske: der
            // Active-Haken wird im Kommandobalken gesetzt, und gerade er ging
            // bisher bei jedem Neustart verloren.
            _scopes.CollectionChanged += (_, e) =>
            {
                foreach (ScanScope scope in e.OldItems?.OfType<ScanScope>() ?? [])
                {
                    scope.PropertyChanged -= OnScopeEdited;
                }
                foreach (ScanScope scope in e.NewItems?.OfType<ScanScope>() ?? [])
                {
                    scope.PropertyChanged += OnScopeEdited;
                }
            };
        }

        /// <summary>
        /// Ein Bereich wurde an- oder abgewaehlt. Der Kommandobalken rechnet
        /// daraufhin Zielzahl, Dauer und Verfahrensverfuegbarkeit neu.
        /// </summary>
        public event Action? SelectionChanged;

        public ObservableCollection<ScanScope> Scopes => _scopes;

        [ObservableProperty] private ScanScope? _selected;

        /// <summary>Ohne Auswahl bleibt die Maske leer statt halb bedienbar.</summary>
        public bool HasSelection => Selected is not null;

        /// <summary>
        /// Der Adapter-Bereich wird beim Start erzeugt, nicht gespeichert - er
        /// laesst sich darum weder loeschen noch sinnvoll bearbeiten.
        /// </summary>
        public bool IsEditable => Selected is not null && Selected.Kind == ScanScopeKind.IPv4Range;

        /// <summary>Was an der Maske nicht stimmt. Leer, wenn alles passt.</summary>
        [ObservableProperty] private string _problem = string.Empty;

        [ObservableProperty] private string _status = string.Empty;

        partial void OnSelectedChanged(ScanScope? value)
        {
            OnPropertyChanged(nameof(HasSelection));
            OnPropertyChanged(nameof(IsEditable));
            Validate();
        }

        /// <summary>
        /// Jede Aenderung an der Maske wird sofort geprueft und gespeichert.
        /// <para>
        /// Kein Speichern-Knopf: die Liste links zeigt bereits, was gilt, und
        /// ein Knopf, den man vergisst, kostet die Arbeit eines ganzen
        /// Formulars. Ungueltige Zwischenstaende - eine halb getippte Adresse -
        /// werden zwar gespeichert, aber angezeigt und beim Scannen
        /// uebersprungen.
        /// </para>
        /// </summary>
        private void OnScopeEdited(object? sender, PropertyChangedEventArgs e)
        {
            // RangeText ist abgeleitet und wird von FirstIP/LastIP mitgemeldet -
            // darauf zu speichern hiesse, jede Aenderung zweimal zu schreiben.
            if (e.PropertyName == nameof(ScanScope.RangeText)) return;

            if (e.PropertyName == nameof(ScanScope.IsSelected)) SelectionChanged?.Invoke();

            if (ReferenceEquals(sender, Selected)) Validate();

            Save();
        }

        // ------------------------------------------------------------- Laden

        /// <summary>
        /// Liest die gespeicherten Bereiche und stellt den Adapter-Bereich
        /// voran, damit ohne jede Einrichtung sofort etwas da ist.
        /// </summary>
        public void Load(string xmlPath)
        {
            _xmlPath = xmlPath;
            _loading = true;

            try
            {
                _scopes.Clear();

                _scopes.Add(new ScanScope
                {
                    Index = 0,
                    Kind = ScanScopeKind.NetworkInterface,
                    GroupDescription = "Local network",
                    DeviceDescription = "from the active adapter",
                    IsSelected = true
                });

                if (!File.Exists(xmlPath)) return;

                // Die Tabelle mit *dem* Schema aufbauen, in dem auch
                // gespeichert wird - nicht mit dem alten IPGroupData.
                //
                // ReadXml traegt in eine Tabelle, die schon Spalten hat, keine
                // unbekannten nach: was die Tabelle nicht kennt, faellt beim
                // Lesen weg. IPGroupData kennt weder ScannedBy noch
                // LastScanned. Beide standen also in der Datei, kamen aber nie
                // zurueck - die Zuordnung eines Bereichs zu einem Satelliten
                // ueberlebte keinen Neustart, und der Bereich wurde danach
                // wieder still von hier aus gescannt.
                System.Data.DataTable data = IpGroupTable.CreateTable();
                data.ReadXml(xmlPath);

                int index = 1;

                foreach (IpGroup group in IpGroupTable.ReadRows(data))
                {
                    ScanScope scope = ScanScope.FromIpGroup(group);
                    scope.Index = index++;
                    _scopes.Add(scope);
                }

                Status = $"{_scopes.Count - 1} ranges loaded.";
            }
            catch (Exception ex)
            {
                // Eine fehlende oder beschaedigte Datei darf den Start nicht
                // verhindern - der Adapter-Bereich genuegt zum Arbeiten.
                Status = $"Ranges could not be loaded: {ex.Message}";
            }
            finally
            {
                _loading = false;
            }
        }

        // --------------------------------------------------------- Speichern

        /// <summary>
        /// Wie lange nach der letzten Aenderung gewartet wird, bevor
        /// geschrieben wird. Die Textfelder melden je Tastendruck - ohne diese
        /// Pause entstuende je Buchstabe ein Dateizugriff.
        /// </summary>
        private static readonly TimeSpan SaveDelay = TimeSpan.FromMilliseconds(600);

        private Timer? _saveTimer;

        /// <summary>
        /// Der Stand, der geschrieben werden soll. Wird beim Anfordern
        /// aufgenommen, nicht beim Schreiben: der Zeitgeber laeuft auf einem
        /// eigenen Thread, und die Bereichsliste gehoert der Oberflaeche.
        /// </summary>
        private List<IpGroup> _pending = [];

        /// <summary>
        /// Ob seit dem Laden ueberhaupt etwas geaendert wurde. Ohne diese
        /// Sperre wuerde blosses Oeffnen und Schliessen der Anwendung die
        /// Datei neu schreiben - unnoetiges Risiko fuer einen Bestand, den auch
        /// die bisherige Oberflaeche liest.
        /// </summary>
        private bool _dirty;

        /// <summary>
        /// Merkt den aktuellen Stand zum Speichern vor. Wird nach jeder
        /// Aenderung aufgerufen, auch nach einem Haken im Kommandobalken -
        /// genau der ging bisher bei jedem Neustart verloren.
        /// </summary>
        public void Save()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath)) return;

            _dirty = true;

            // Aufnehmen, solange wir noch auf dem Oberflaechen-Thread sind.
            _pending =
            [
                .. _scopes.OrderBy(s => s.Index)
                          .Select(s => s.ToIpGroup())
                          .Where(g => g is not null)
                          .Select(g => g!)
            ];

            _saveTimer ??= new Timer(_ => Flush(), null, Timeout.Infinite, Timeout.Infinite);
            _saveTimer.Change(SaveDelay, Timeout.InfiniteTimeSpan);
        }

        /// <summary>Schreibt den vorgemerkten Stand. Laeuft auf dem Zeitgeber-Thread.</summary>
        private void Flush()
        {
            try
            {
                IpGroupTable.SaveXml(_pending, _xmlPath);
            }
            catch (Exception ex)
            {
                Status = $"Ranges could not be saved: {ex.Message}";
            }
        }

        /// <summary>
        /// Schreibt sofort, ohne die Pause abzuwarten - beim Schliessen des
        /// Fensters, wo der Zeitgeber sonst nie mehr feuern wuerde.
        /// </summary>
        public void SaveNow()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath) || !_dirty) return;

            Save();
            _saveTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            Flush();
        }

        // ----------------------------------------------------------- Befehle

        [RelayCommand]
        private void Add()
        {
            ScanScope scope = new()
            {
                Index = NextIndex(),
                Kind = ScanScopeKind.IPv4Range,
                GroupDescription = "New range",
                FirstIP = "192.168.1.1",
                LastIP = "192.168.1.254",
                IsSelected = false
            };

            _scopes.Add(scope);
            Selected = scope;
            Save();

            Status = "Range added.";
        }

        /// <summary>
        /// Ein neuer Bereich unterscheidet sich vom vorigen meist nur im
        /// dritten Oktett - Kopieren ist darum der schnellere Weg als das
        /// Formular erneut auszufuellen.
        /// </summary>
        [RelayCommand]
        private void Duplicate()
        {
            if (Selected is null) return;

            ScanScope copy = new()
            {
                Index = NextIndex(),
                Kind = ScanScopeKind.IPv4Range,
                GroupDescription = $"{Selected.GroupDescription} (copy)",
                DeviceDescription = Selected.DeviceDescription,
                FirstIP = Selected.FirstIP,
                LastIP = Selected.LastIP,
                Domain = Selected.Domain,
                DnsServers = Selected.DnsServers,
                GatewayIP = Selected.GatewayIP,
                ScannedBy = Selected.ScannedBy,
                AutomaticScan = Selected.AutomaticScan,
                ScanIntervalMinutes = Selected.ScanIntervalMinutes,
                // LastScanned wird bewusst nicht mitkopiert: die Kopie ist noch
                // nie gelaufen, sonst gaelte sie sofort als frisch gescannt.
                IsSelected = false
            };

            _scopes.Add(copy);
            Selected = copy;
            Save();

            Status = "Range duplicated.";
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected is null || !IsEditable) return;

            string name = Selected.GroupDescription;
            int position = _scopes.IndexOf(Selected);

            _scopes.Remove(Selected);

            // Die naechstliegende Zeile waehlen, statt in eine leere Maske zu
            // fallen - meistens will man gleich weiterarbeiten.
            Selected = _scopes.Count == 0
                ? null
                : _scopes[Math.Min(position, _scopes.Count - 1)];

            Save();
            Status = $"\"{name}\" deleted.";
        }

        private int NextIndex() =>
            _scopes.Count == 0 ? 1 : _scopes.Max(s => s.Index) + 1;

        // ----------------------------------------------------------- Pruefung

        private void Validate()
        {
            if (Selected is null || !IsEditable)
            {
                Problem = string.Empty;
                return;
            }

            Problem = Selected.TryValidate(out string? problem) ? string.Empty : problem ?? string.Empty;
        }
    }
}
