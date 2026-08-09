namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Welche Dienste in der Tabellenspalte einzeln stehen und welche zu
    /// einem "+n" zusammengefasst werden.
    /// <para>
    /// Standardmaessig wird <b>nichts</b> zusammengefasst: wer eine Spalte
    /// "Running services" liest, will wissen, was laeuft. Die fruehere feste
    /// Grenze bei drei Namen hat die Antwort hinter einem "+5" versteckt, und
    /// zwar ausgerechnet bei den Geraeten mit den meisten Diensten - also
    /// dort, wo es am meisten zu sehen gab.
    /// </para>
    /// <para>
    /// Bewusst statisch. Die Spalte bindet unmittelbar an <see cref="Device"/>,
    /// und ein Geraet traegt keinen Verweis auf die Einstellungen - es kommt
    /// aus dem Netz, nicht aus der Oberflaeche. Eine Anzeigeoption ueber das
    /// ganze Fenster hinweg ist der eine Fall, in dem das vertretbar ist.
    /// </para>
    /// </summary>
    public static class ServiceDisplay
    {
        /// <summary>
        /// Die ausgewaehlten Dienste zusammenfassen. Aus bedeutet: alle
        /// einzeln zeigen.
        /// </summary>
        public static bool GroupSelected { get; set; }

        /// <summary>
        /// Die Dienste, die zusammengefasst werden - der Nutzer waehlt sie
        /// selbst. Gedacht fuer das, was auf jedem zweiten Geraet steht und
        /// darum nichts unterscheidet.
        /// </summary>
        public static HashSet<string> Grouped { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Offene TCP-Ports ohne erkannten Dienst zu einem Chip "TCP Ports"
        /// zusammenfassen, statt jeden einzeln als "TCP 8080", "TCP 8443" usw.
        /// zu zeigen. Anders als bei <see cref="Grouped"/> steht hier keine
        /// feste Namensliste dahinter, sondern jeder Fund der Form "TCP {Port}"
        /// - genau die Faelle, in denen ein Geraet mit vielen offenen Ports die
        /// Spalte sonst sprengt. Standardmaessig an, weil das der Fall ist, der
        /// die Spalte am haeufigsten unlesbar macht.
        /// </summary>
        public static bool GroupTcpPorts { get; set; } = true;

        /// <summary>Dasselbe fuer UDP-Ports, siehe <see cref="GroupTcpPorts"/>.</summary>
        public static bool GroupUdpPorts { get; set; } = true;

        /// <summary>
        /// Die Einstellung hat sich geaendert. Die Geraeteliste haengt sich
        /// hier ein und laesst die Spalte neu zeichnen - berechnete
        /// Eigenschaften melden sich nicht von allein.
        /// </summary>
        public static event Action? Changed;

        public static void NotifyChanged() => Changed?.Invoke();

        /// <summary>
        /// Teilt die Dienstnamen eines Geraets in "einzeln zeigen" und "zaehlt
        /// zum +n".
        /// </summary>
        public static (IReadOnlyList<string> Shown, int Folded) Split(IReadOnlyList<string> names)
        {
            if (!GroupSelected || Grouped.Count == 0) return (names, 0);

            List<string> shown = [.. names.Where(n => !Grouped.Contains(n))];

            return (shown, names.Count - shown.Count);
        }
    }
}
