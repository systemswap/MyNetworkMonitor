// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// What the satellites of the current run are doing, as one sentence for the status line: which
    /// are still scanning, which have reported, which were not connected, which ended with an error.
    /// <para>
    /// The status line is rewritten by the local run all the time, and a satellite usually finishes
    /// before it. A note set once when the jobs were sent would therefore say "scanning" long after the
    /// results arrived, and the end of the local run would put exactly that note back
    /// (docs/FEHLERGEDAECHTNIS.md, No. 42). Keeping the state here lets every rewrite show the
    /// current one.
    /// </para>
    /// </summary>
    public sealed class SatelliteRunTracker
    {
        private readonly List<string> _scanning = [];
        private readonly List<string> _missing = [];
        private readonly List<string> _ended = [];

        /// <summary>Forgets the previous run.</summary>
        public void Clear()
        {
            _scanning.Clear();
            _missing.Clear();
            _ended.Clear();
        }

        /// <summary>The jobs have been sent.</summary>
        /// <param name="scanning">Satellites that accepted their job.</param>
        /// <param name="missing">Satellites whose ranges were not scanned because they are not connected.</param>
        public void Start(IEnumerable<string> scanning, IEnumerable<string> missing)
        {
            Clear();
            _scanning.AddRange(scanning);
            _missing.AddRange(missing);
        }

        /// <summary>A satellite delivered its result.</summary>
        /// <param name="name">The satellite.</param>
        /// <param name="devices">The number of devices taken over.</param>
        /// <param name="partial">The job was stopped before it was complete.</param>
        public void Finished(string name, int devices, bool partial)
        {
            _scanning.RemoveAll(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
            _ended.Add(partial
                ? $"\"{name}\" was stopped - {devices} device(s) found so far (range not fully scanned)"
                : $"\"{name}\" reported {devices} device(s)");
        }

        /// <summary>A satellite ended its job without a result: error, busy, cancelled.</summary>
        /// <param name="name">The satellite.</param>
        /// <param name="text">What it reported.</param>
        public void Failed(string name, string text)
        {
            _scanning.RemoveAll(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
            _ended.Add($"\"{name}\": {text}");
        }

        /// <summary>The satellites still working.</summary>
        public IReadOnlyList<string> Scanning => _scanning;

        /// <summary>The sentence for the status line; empty if no satellite takes part.</summary>
        public string Note
        {
            get
            {
                List<string> parts = [];

                if (_scanning.Count == 1) parts.Add($"Satellite \"{_scanning[0]}\" is scanning");
                else if (_scanning.Count > 1) parts.Add($"{_scanning.Count} satellites are scanning ({string.Join(", ", _scanning)})");

                parts.AddRange(_ended);

                if (_missing.Count == 1) parts.Add($"\"{_missing[0]}\" is not connected - its ranges were not scanned");
                else if (_missing.Count > 1) parts.Add($"{_missing.Count} satellites are not connected - their ranges were not scanned");

                return string.Join(" · ", parts);
            }
        }
    }
}
