using System.Runtime.Versioning;
using System.Security.Principal;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Access to Windows Firewall through its COM interface
    /// (<c>HNetCfg.FwPolicy2</c>).
    /// <para>
    /// Uses COM on purpose instead of parsing <c>netsh advfirewall</c>: its
    /// output is localized. The columns are named differently on a German and
    /// an English Windows, so text parsing would break depending on the system
    /// language.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsFirewallInspector : IFirewallInspector
    {
        // Constants of the firewall COM interface.
        private const int DirectionIn = 1;
        private const int ActionAllow = 1;
        private const int ProtocolTcp = 6;
        private const int ProtocolUdp = 17;

        public bool IsSupported => OperatingSystem.IsWindows();

        /// <summary>
        /// Only an elevated process may create rules. Without this check the
        /// attempt would end in a meaningless COM error.
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

                // Only the profiles currently in effect: a rule that applies only
                // to the public profile does not help in a company network.
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
                        // A single broken rule must not spoil the list: some
                        // rules throw when individual fields are read.
                    }
                }
            }
            catch
            {
                // No access to the firewall service: no list.
                return [];
            }

            // The same port specification appearing several times is common.
            // The display needs it once, and the most informative one: a rule
            // that applies to every program is the useful answer.
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

                // If the rule already exists, it is updated instead of creating
                // a second one; otherwise every port change would leave a stale
                // rule behind.
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

                // Bound to this application instead of opening the port for
                // everything: the permission applies to this program only.
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
        /// Finds a rule by name. Iterates the collection instead of calling
        /// <c>Rules.Item(name)</c>: that throws when the rule does not exist, and
        /// an exception as the normal case is expensive and hard to follow.
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
