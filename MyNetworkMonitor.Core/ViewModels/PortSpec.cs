using System.Globalization;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Eine Porteingabe des Nutzers, wie sie im Filterfeld steht: eine einzelne
    /// Nummer, mehrere durch Komma getrennt oder ein Bereich - auch gemischt.
    /// <para>
    /// Beispiele: <c>445</c>, <c>80,443</c>, <c>5000-5100</c>,
    /// <c>22, 80, 8000-8100</c>.
    /// </para>
    /// </summary>
    public sealed class PortSpec
    {
        private readonly List<int> _single = [];
        private readonly List<(int From, int To)> _ranges = [];

        /// <summary>Es wurde nichts Brauchbares eingegeben - der Filter greift dann nicht.</summary>
        public bool IsEmpty => _single.Count == 0 && _ranges.Count == 0;

        /// <summary>
        /// Der Text enthielt etwas, das sich nicht als Port lesen liess. Die
        /// Oberflaeche faerbt das Feld daraufhin ein, statt stillschweigend
        /// nichts zu filtern.
        /// </summary>
        public bool HasInvalidPart { get; private init; }

        public static PortSpec Empty { get; } = new();

        /// <summary>
        /// Liest die Eingabe. Wirft nicht - unbrauchbare Teile werden
        /// uebersprungen und ueber <see cref="HasInvalidPart"/> gemeldet.
        /// </summary>
        public static PortSpec Parse(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return Empty;

            PortSpec spec = new();
            bool invalid = false;

            foreach (string part in text.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                int dash = part.IndexOf('-');

                if (dash > 0 && dash < part.Length - 1)
                {
                    if (TryPort(part[..dash], out int from) && TryPort(part[(dash + 1)..], out int to))
                    {
                        // Verdrehte Eingabe wie 8100-8000 wohlwollend deuten.
                        spec._ranges.Add(from <= to ? (from, to) : (to, from));
                    }
                    else
                    {
                        invalid = true;
                    }
                }
                else if (TryPort(part, out int single))
                {
                    spec._single.Add(single);
                }
                else
                {
                    invalid = true;
                }
            }

            if (!invalid) return spec;

            PortSpec flagged = new() { HasInvalidPart = true };
            flagged._single.AddRange(spec._single);
            flagged._ranges.AddRange(spec._ranges);
            return flagged;
        }

        public bool Contains(int port) =>
            _single.Contains(port) || _ranges.Any(r => port >= r.From && port <= r.To);

        public bool ContainsAny(IEnumerable<int> ports) => ports.Any(Contains);

        private static bool TryPort(string text, out int port) =>
            int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port)
            && port is >= 0 and <= 65535;

        public override string ToString()
        {
            if (IsEmpty) return "(leer)";

            IEnumerable<string> parts =
                _single.Select(p => p.ToString(CultureInfo.InvariantCulture))
                       .Concat(_ranges.Select(r => $"{r.From}-{r.To}"));

            return string.Join(", ", parts);
        }
    }
}
