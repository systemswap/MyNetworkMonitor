using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Persistence;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Die Verwaltung der Satelliten: Liste links, Maske rechts - dasselbe
    /// Muster wie bei den Bereichen.
    /// <para>
    /// Der Entwurf steht in SATELLIT.md. Solange der Satellitenbetrieb nicht
    /// gebaut ist, legt man Eintraege von Hand an: Name vergeben, Bereiche
    /// darauf zeigen lassen, fertig. Sobald sich ein Satellit meldet, traegt
    /// er Fingerabdruck, Version und Herkunft selbst nach und wartet auf die
    /// Freigabe.
    /// </para>
    /// </summary>
    public partial class SatelliteEditorViewModel : ObservableObject
    {
        private string _filePath = string.Empty;
        private bool _loading;

        /// <summary>Alle Satelliten - die Liste, an der auch die Bereichsmaske haengt.</summary>
        public ObservableCollection<Satellite> All { get; } = [];

        [ObservableProperty] private Satellite? _selected;

        [ObservableProperty] private string _status = string.Empty;

        /// <summary>
        /// Die Namen fuer die Auswahl in der Bereichsmaske, mit einem leeren
        /// Eintrag voran - der bedeutet "von diesem Rechner aus".
        /// </summary>
        public ObservableCollection<string> NamesForPicker { get; } = [string.Empty];

        /// <summary>Meldet sich, wenn ein Name hinzukam, wegfiel oder sich aenderte.</summary>
        public event Action? NamesChanged;

        public SatelliteEditorViewModel()
        {
            All.CollectionChanged += (_, e) =>
            {
                foreach (Satellite s in e.OldItems?.OfType<Satellite>() ?? [])
                {
                    s.PropertyChanged -= OnSatelliteEdited;
                }
                foreach (Satellite s in e.NewItems?.OfType<Satellite>() ?? [])
                {
                    s.PropertyChanged += OnSatelliteEdited;
                }

                RefreshNames();
                Save();
            };
        }

        private void OnSatelliteEdited(object? sender, PropertyChangedEventArgs e)
        {
            // IsConnected wird nicht gespeichert und soll darum auch nicht
            // jedes Mal eine Schreibrunde ausloesen.
            if (e.PropertyName == nameof(Satellite.IsConnected)) return;

            if (e.PropertyName == nameof(Satellite.Name)) RefreshNames();

            Save();
        }

        private void RefreshNames()
        {
            NamesForPicker.Clear();
            NamesForPicker.Add(string.Empty);

            foreach (string name in All.Select(s => s.Name)
                                       .Where(n => !string.IsNullOrWhiteSpace(n))
                                       .Distinct(StringComparer.OrdinalIgnoreCase)
                                       .OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
            {
                NamesForPicker.Add(name);
            }

            NamesChanged?.Invoke();
        }

        // ------------------------------------------------------------- Laden

        public void Load(string settingsFolder)
        {
            _filePath = Path.Combine(settingsFolder, SatelliteFile.DefaultFileName);
            _loading = true;

            try
            {
                All.Clear();
                foreach (Satellite s in SatelliteFile.Load(_filePath)) All.Add(s);

                Status = All.Count == 0
                    ? "No satellites yet."
                    : $"{All.Count} satellite(s) loaded.";
            }
            finally
            {
                _loading = false;
                RefreshNames();
            }
        }

        // --------------------------------------------------------- Speichern

        public void Save()
        {
            if (_loading || string.IsNullOrEmpty(_filePath)) return;

            try
            {
                SatelliteFile.Save(All, _filePath);
            }
            catch (Exception ex)
            {
                Status = $"Satellites could not be saved: {ex.Message}";
            }
        }

        // ----------------------------------------------------------- Befehle

        /// <summary>
        /// Nimmt einen Satelliten auf, der sich gerade gemeldet hat, oder
        /// bringt einen bekannten auf den neuesten Stand.
        /// <para>
        /// Es gibt bewusst kein Anlegen von Hand: der Satellit nennt seinen
        /// Namen selbst, sobald er sich verbindet. Ein hier eingetippter Name
        /// waere eine Behauptung, die beim ersten Verbinden ohnehin
        /// ueberschrieben wuerde.
        /// </para>
        /// <para>
        /// Wiedererkannt wird am Fingerabdruck, nicht am Namen - benennt sich
        /// ein Satellit um, bleibt es derselbe Eintrag samt Freigabe. Nur wenn
        /// der Fingerabdruck neu ist, entsteht ein neuer Eintrag, und der
        /// wartet auf Freigabe.
        /// </para>
        /// </summary>
        public Satellite Announce(string name, string fingerprint, string version, string os, string remoteAddress)
        {
            Satellite? known = All.FirstOrDefault(s =>
                !string.IsNullOrWhiteSpace(fingerprint) &&
                string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

            if (known is null)
            {
                known = new Satellite { Fingerprint = fingerprint, Approved = false };
                All.Add(known);
                Status = $"\"{name}\" has announced itself and is waiting for approval.";
            }

            known.Name = string.IsNullOrWhiteSpace(name) ? known.Name : name;
            known.Version = version;
            known.Os = os;
            known.RemoteAddress = remoteAddress;
            known.LastSeen = DateTimeOffset.Now;
            known.IsConnected = true;

            Save();
            return known;
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected is null) return;

            string gone = Selected.Name;
            All.Remove(Selected);
            Selected = All.FirstOrDefault();

            // Die Bereiche zeigen jetzt womoeglich auf einen Namen, den es
            // nicht mehr gibt. Aufgeraeumt wird das nicht hier, sondern beim
            // Lauf: ein unbekannter Name gilt als "nicht verbunden", und der
            // Bereich wird uebersprungen statt stillschweigend oertlich
            // gescannt (SATELLIT.md, Abschnitt 3).
            Status = $"\"{gone}\" removed. Ranges still pointing at it will be reported as not scanned.";
        }

        /// <summary>
        /// Nimmt die Freigabe zurueck. Der Satellit darf sich weiter melden,
        /// bekommt aber keine Auftraege mehr, bis er erneut freigegeben wird.
        /// </summary>
        [RelayCommand]
        private void Revoke()
        {
            if (Selected is null) return;

            Selected.Approved = false;
            Status = $"Approval for \"{Selected.Name}\" withdrawn.";
        }

        /// <summary>Gibt den ausgewaehlten Satelliten frei - der eine Klick aus SATELLIT.md.</summary>
        [RelayCommand]
        private void Approve()
        {
            if (Selected is null) return;

            Selected.Approved = true;
            Status = $"\"{Selected.Name}\" approved.";
        }

    }
}
