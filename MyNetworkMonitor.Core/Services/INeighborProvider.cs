using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Zustand eines Nachbareintrags. Entspricht den Zustaenden aus RFC 4861 und
    /// ist unter Windows wie Linux dasselbe - beide fuehren dieselbe
    /// Zustandsmaschine, nur unter anderen Namen.
    /// <para>
    /// Der Zustand ist kein Beiwerk: <see cref="Incomplete"/> und
    /// <see cref="Failed"/> heissen "diese Adresse wurde angefragt, es kam aber
    /// nie eine Antwort". Solche Eintraege als gefundenes Geraet zu melden waere
    /// falsch - sie bezeugen nur den eigenen Versuch.
    /// </para>
    /// </summary>
    public enum NeighborState
    {
        Unknown = 0,

        /// <summary>Angefragt, noch keine Antwort. Kein Geraet.</summary>
        Incomplete,

        /// <summary>Aufgegeben, es antwortet niemand. Kein Geraet.</summary>
        Failed,

        /// <summary>Eintrag vorhanden, aber laenger nicht bestaetigt.</summary>
        Stale,

        /// <summary>Wird gerade nachgeprueft.</summary>
        Delay,

        /// <summary>Nachfrage laeuft.</summary>
        Probe,

        /// <summary>Kuerzlich bestaetigt - das Geraet ist da.</summary>
        Reachable,

        /// <summary>Fest eingetragen, wird nie geprueft.</summary>
        Permanent
    }

    /// <summary>
    /// Ein Eintrag aus der Nachbarschaftstabelle des Betriebssystems - das
    /// IPv6-Gegenstueck zu <see cref="Models.ArpEntry"/>.
    /// <para>
    /// Reichhaltiger als der ARP-Eintrag, und das mit Absicht: unter IPv6 traegt
    /// die Tabelle zusaetzlich den Zustand und das Router-Merkmal. Beides ist
    /// auswertbar - <see cref="IsRouter"/> benennt den Router im Segment, ohne
    /// dass ein einziges Paket gesendet wurde.
    /// </para>
    /// </summary>
    public sealed class NeighborEntry
    {
        public required IPAddress Address { get; init; }

        /// <summary>Fehlt bei Eintraegen, die nie beantwortet wurden.</summary>
        public PhysicalAddress? Mac { get; init; }

        /// <summary>Index des Adapters, ueber den der Nachbar erreichbar ist.</summary>
        public int InterfaceIndex { get; init; }

        /// <summary>Name des Adapters, soweit die Plattform ihn mitliefert.</summary>
        public string? InterfaceName { get; init; }

        public NeighborState State { get; init; } = NeighborState.Unknown;

        /// <summary>Der Nachbar hat sich als Router zu erkennen gegeben.</summary>
        public bool IsRouter { get; init; }

        /// <summary>
        /// Der Eintrag bezeugt ein tatsaechlich vorhandenes Geraet. Ein blosser
        /// Anfrageversuch ohne Antwort tut das nicht.
        /// </summary>
        public bool IsUsable =>
            State is not (NeighborState.Incomplete or NeighborState.Failed or NeighborState.Unknown) &&
            Mac is not null;

        public override string ToString() =>
            $"{Address} {Mac?.ToString() ?? "-"} [{State}]{(IsRouter ? " router" : "")}";
    }

    /// <summary>
    /// Liest die Nachbarschaftstabelle (Neighbor Cache) des Betriebssystems.
    /// <para>
    /// Eigene Schnittstelle statt einer Erweiterung von
    /// <see cref="IArpProvider"/>: der ARP-Anbieter liefert Zeichenketten und
    /// kennt weder Zustand noch Adapter, und seine Windows-Fassung parst die
    /// Ausgabe von <c>arp -a</c>. Fuer IPv6 reicht das nicht - dort braucht es
    /// den Zustand, um Anfrageversuche von echten Nachbarn zu trennen.
    /// </para>
    /// </summary>
    public interface INeighborProvider
    {
        /// <summary>
        /// Alle Eintraege beider Adressfamilien. Wirft nicht - laesst sich die
        /// Tabelle nicht lesen, kommt eine leere Liste zurueck.
        /// </summary>
        Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken cancellationToken = default);
    }
}
