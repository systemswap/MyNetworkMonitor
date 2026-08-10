namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Eine eingehend erlaubte Portangabe aus der oertlichen Firewall.
    /// </summary>
    /// <param name="Protocol">TCP oder UDP.</param>
    /// <param name="Ports">Einzelner Port oder Bereich, wie die Regel es sagt (z. B. "5900-5904").</param>
    /// <param name="RuleName">Name der Regel - damit man erkennt, wozu der Port gehoert.</param>
    /// <param name="AnyProgram">
    /// Die Regel gilt fuer <b>jedes</b> Programm. Nur solche Ports lassen sich
    /// ohne neue Regel benutzen: eine Regel, die an ein bestimmtes Programm
    /// gebunden ist, hilft einer anderen Anwendung nicht.
    /// </param>
    public readonly record struct AllowedInboundPort(
        string Protocol,
        string Ports,
        string RuleName,
        bool AnyProgram);

    /// <summary>Ergebnis eines Versuchs, eine Regel anzulegen oder zu entfernen.</summary>
    /// <param name="Success">Hat geklappt.</param>
    /// <param name="Message">Klartext fuer den Nutzer - auch im Erfolgsfall.</param>
    public readonly record struct FirewallChangeResult(bool Success, string Message);

    /// <summary>
    /// Zugriff auf die oertliche Firewall: lesen, welche eingehenden Ports
    /// erlaubt sind, und - mit erhoehten Rechten - eine eigene Regel anlegen.
    /// <para>
    /// Zweck ist der Lauschport des Hauptscanners. Wer keine Rechte hat, sucht
    /// sich einen Port, der ohnehin offen ist; wer Administrator ist, legt sich
    /// den gewuenschten Port selbst an. Beides soll die Oberflaeche koennen.
    /// </para>
    /// <para>
    /// Angelegt wird ausschliesslich eine Regel <b>fuer diese Anwendung</b>,
    /// mit erkennbarem Namen und auf genau einen Port. Nichts wird pauschal
    /// geoeffnet, und bestehende Regeln werden nicht angefasst.
    /// </para>
    /// </summary>
    public interface IFirewallInspector
    {
        /// <summary>Ob auf dieser Plattform ueberhaupt gelesen werden kann.</summary>
        bool IsSupported { get; }

        /// <summary>
        /// Alle aktiven Erlaubnisregeln fuer eingehende Verbindungen mit
        /// konkreter Portangabe. Leer, wenn nichts gelesen werden konnte.
        /// </summary>
        IReadOnlyList<AllowedInboundPort> ReadAllowedInbound();

        /// <summary>
        /// Ob eine Regel angelegt werden darf - also ob die Anwendung mit
        /// erhoehten Rechten laeuft.
        /// </summary>
        bool CanCreateRule { get; }

        /// <summary>
        /// Legt eine eingehende Erlaubnis fuer diese Anwendung auf dem
        /// angegebenen TCP-Port an. Gibt es sie schon, wird sie auf den neuen
        /// Port gesetzt statt eine zweite anzulegen.
        /// </summary>
        FirewallChangeResult AllowInboundTcp(int port, string ruleName);

        /// <summary>Entfernt eine zuvor angelegte Regel wieder.</summary>
        FirewallChangeResult RemoveRule(string ruleName);
    }

    /// <summary>Wenn keine Umsetzung da ist - meldet schlicht, dass es nicht geht.</summary>
    public sealed class NullFirewallInspector : IFirewallInspector
    {
        public bool IsSupported => false;
        public bool CanCreateRule => false;

        public IReadOnlyList<AllowedInboundPort> ReadAllowedInbound() => [];

        public FirewallChangeResult AllowInboundTcp(int port, string ruleName) =>
            new(false, "Reading or changing firewall rules is not supported on this platform.");

        public FirewallChangeResult RemoveRule(string ruleName) =>
            new(false, "Reading or changing firewall rules is not supported on this platform.");
    }
}
