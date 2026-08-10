using System.Runtime.Versioning;
using System.Security.Principal;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Zugriff auf die Windows-Firewall ueber deren COM-Schnittstelle
    /// (<c>HNetCfg.FwPolicy2</c>).
    /// <para>
    /// Bewusst COM und nicht das Auswerten von <c>netsh advfirewall</c>: dessen
    /// Ausgabe ist uebersetzt. Auf einem deutschen Windows heissen die Spalten
    /// anders als auf einem englischen, und ein Auswerten nach Text waere je
    /// nach Sprache des Rechners kaputt.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsFirewallInspector : IFirewallInspector
    {
        // Werte der Firewall-COM-Schnittstelle.
        private const int DirectionIn = 1;
        private const int ActionAllow = 1;
        private const int ProtocolTcp = 6;
        private const int ProtocolUdp = 17;

        public bool IsSupported => OperatingSystem.IsWindows();

        /// <summary>
        /// Regeln anlegen darf nur, wer erhoeht laeuft. Ohne diese Pruefung
        /// wuerde der Versuch mit einem nichtssagenden COM-Fehler enden.
        /// </summary>
        public bool CanCreateRule
        {
            get
            {
                if (!OperatingSystem.IsWindows()) return false;

                try
                {
                    using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch
                {
                    return false;
                }
            }
        }

        public IReadOnlyList<AllowedInboundPort> ReadAllowedInbound()
        {
            if (!IsSupported) return [];

            List<AllowedInboundPort> found = [];

            try
            {
                dynamic? policy = CreatePolicy();
                if (policy is null) return [];

                // Nur die Profile, die gerade gelten: eine Regel, die allein im
                // oeffentlichen Profil greift, hilft im Firmennetz nicht.
                int active = (int)policy.CurrentProfileTypes;

                foreach (dynamic rule in policy.Rules)
                {
                    try
                    {
                        if (!(bool)rule.Enabled) continue;
                        if ((int)rule.Direction != DirectionIn) continue;
                        if ((int)rule.Action != ActionAllow) continue;

                        int protocol = (int)rule.Protocol;
                        if (protocol is not (ProtocolTcp or ProtocolUdp)) continue;

                        if (((int)rule.Profiles & active) == 0) continue;

                        string? ports = rule.LocalPorts as string;
                        if (string.IsNullOrWhiteSpace(ports) ||
                            ports.Equals("*", StringComparison.Ordinal)) continue;

                        string? program = rule.ApplicationName as string;

                        found.Add(new AllowedInboundPort(
                            Protocol: protocol == ProtocolTcp ? "TCP" : "UDP",
                            Ports: ports,
                            RuleName: rule.Name as string ?? string.Empty,
                            AnyProgram: string.IsNullOrWhiteSpace(program)));
                    }
                    catch
                    {
                        // Eine einzelne kaputte Regel darf die Liste nicht
                        // kippen - es gibt Regeln, die beim Auslesen einzelner
                        // Felder werfen.
                    }
                }
            }
            catch
            {
                // Kein Zugriff auf den Firewall-Dienst: dann eben keine Liste.
                return [];
            }

            // Gleiche Portangabe mehrfach ist die Regel, nicht die Ausnahme -
            // fuer die Anzeige genuegt sie einmal, und zwar die aussagekraeftigste:
            // gilt sie fuer jedes Programm, ist das die brauchbare Auskunft.
            return [.. found
                .GroupBy(p => (p.Protocol, p.Ports))
                .Select(g => g.OrderByDescending(p => p.AnyProgram).First())
                .OrderBy(p => p.Protocol, StringComparer.Ordinal)
                .ThenBy(p => p.Ports, StringComparer.Ordinal)];
        }

        public FirewallChangeResult AllowInboundTcp(int port, string ruleName)
        {
            if (!IsSupported) return new(false, "Not supported on this platform.");
            if (port is < 1 or > 65535) return new(false, $"{port} is not a valid port.");
            if (string.IsNullOrWhiteSpace(ruleName)) return new(false, "The rule needs a name.");

            if (!CanCreateRule)
            {
                return new(false,
                    "Creating a firewall rule needs elevated rights. Restart as administrator, " +
                    "or pick a port that is already open.");
            }

            try
            {
                dynamic? policy = CreatePolicy();
                if (policy is null) return new(false, "The firewall service could not be reached.");

                // Gibt es die eigene Regel schon, wird sie umgestellt statt
                // eine zweite anzulegen - sonst sammeln sich bei jedem
                // Portwechsel Leichen an.
                dynamic? existing = FindByName(policy, ruleName);

                if (existing is not null)
                {
                    existing.LocalPorts = port.ToString();
                    existing.Enabled = true;
                    return new(true, $"Existing rule \"{ruleName}\" now allows TCP {port}.");
                }

                Type? ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
                if (ruleType is null) return new(false, "The firewall service could not be reached.");

                dynamic? rule = Activator.CreateInstance(ruleType);
                if (rule is null) return new(false, "The rule could not be created.");

                rule.Name = ruleName;
                rule.Description = "Lets satellites of MyNetworkMonitor connect to this machine.";
                rule.Protocol = ProtocolTcp;
                rule.LocalPorts = port.ToString();
                rule.Direction = DirectionIn;
                rule.Action = ActionAllow;
                rule.Enabled = true;

                // An die eigene Anwendung gebunden statt den Port pauschal zu
                // oeffnen: die Erlaubnis gilt damit nur diesem Programm.
                string? self = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(self)) rule.ApplicationName = self;

                rule.Profiles = policy.CurrentProfileTypes;

                policy.Rules.Add(rule);

                return new(true, $"Rule \"{ruleName}\" created: TCP {port} inbound, for this application only.");
            }
            catch (UnauthorizedAccessException)
            {
                return new(false, "Denied by policy - your organisation manages this firewall.");
            }
            catch (Exception ex)
            {
                return new(false, $"The rule could not be created: {ex.Message}");
            }
        }

        public FirewallChangeResult RemoveRule(string ruleName)
        {
            if (!IsSupported) return new(false, "Not supported on this platform.");
            if (string.IsNullOrWhiteSpace(ruleName)) return new(false, "The rule needs a name.");
            if (!CanCreateRule) return new(false, "Removing a firewall rule needs elevated rights.");

            try
            {
                dynamic? policy = CreatePolicy();
                if (policy is null) return new(false, "The firewall service could not be reached.");

                if (FindByName(policy, ruleName) is null)
                {
                    return new(true, $"There is no rule called \"{ruleName}\".");
                }

                policy.Rules.Remove(ruleName);
                return new(true, $"Rule \"{ruleName}\" removed.");
            }
            catch (Exception ex)
            {
                return new(false, $"The rule could not be removed: {ex.Message}");
            }
        }

        private static dynamic? CreatePolicy()
        {
            Type? type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            return type is null ? null : Activator.CreateInstance(type);
        }

        /// <summary>
        /// Sucht eine Regel nach Namen. Ueber die Sammlung statt ueber
        /// <c>Rules.Item(name)</c>: das wirft, wenn es sie nicht gibt, und eine
        /// Ausnahme als Normalfall ist teuer und unuebersichtlich.
        /// </summary>
        private static dynamic? FindByName(dynamic policy, string ruleName)
        {
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    if (string.Equals(rule.Name as string, ruleName, StringComparison.OrdinalIgnoreCase))
                    {
                        return rule;
                    }
                }
                catch { }
            }

            return null;
        }
    }
}
