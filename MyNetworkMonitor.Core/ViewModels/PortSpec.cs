// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Globalization;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// A port specification as entered in the filter field: a single number,
    /// several separated by commas, or a range, also mixed.
    /// <para>
    /// Examples: <c>445</c>, <c>80,443</c>, <c>5000-5100</c>,
    /// <c>22, 80, 8000-8100</c>.
    /// </para>
    /// </summary>
    public sealed class PortSpec
    {
        private readonly List<int> _single = [];
        private readonly List<(int From, int To)> _ranges = [];

        /// <summary>Nothing usable was entered; the filter is then inactive.</summary>
        public bool IsEmpty => _single.Count == 0 && _ranges.Count == 0;

        /// <summary>
        /// The text contained a part that could not be read as a port. The UI
        /// highlights the field instead of silently filtering nothing.
        /// </summary>
        public bool HasInvalidPart { get; private init; }

        /// <summary>An empty specification that matches no port.</summary>
        public static PortSpec Empty { get; } = new();

        /// <summary>
        /// Parses the input. Does not throw; unusable parts are skipped and
        /// reported through <see cref="HasInvalidPart"/>.
        /// </summary>
        /// <param name="text">Ports and ranges separated by commas or semicolons, e.g. <c>22, 80, 8000-8100</c>.</param>
        /// <returns>The parsed specification; <see cref="Empty"/> for blank input.</returns>
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
                        // Accept reversed ranges such as 8100-8000.
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

        /// <summary>Whether the port is one of the single ports or inside one of the ranges.</summary>
        public bool Contains(int port) =>
            _single.Contains(port) || _ranges.Any(r => port >= r.From && port <= r.To);

        /// <summary>Whether at least one of the ports matches.</summary>
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
