// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Splits a line of the terse output of nmcli (<c>-t</c>) into its fields.
    /// </summary>
    /// <remarks>
    /// Fields are separated by ":"; a ":" or "\" inside a value is escaped with a backslash (nmcli(1), option
    /// <c>--escape</c>, on by default). A network name such as "Cafe:Gast" therefore arrives as <c>Cafe\:Gast</c>, and a
    /// plain split at ":" would cut it in two (docs/FEHLERGEDAECHTNIS.md, No. 24).
    /// </remarks>
    public static class NmcliTerse
    {
        /// <summary>Splits one line into its unescaped fields.</summary>
        /// <param name="line">A line of <c>nmcli -t</c> output, without the line break.</param>
        /// <returns>The fields in order; an empty line gives one empty field.</returns>
        public static IReadOnlyList<string> SplitFields(string line)
        {
            List<string> fields = [];
            StringBuilder current = new();
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '\\' && i + 1 < line.Length)
                {
                    current.Append(line[++i]);
                }
                else if (c == ':')
                {
                    fields.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }
            fields.Add(current.ToString());
            return fields;
        }
    }
}
