// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// A port allowed for inbound traffic by the local firewall.
    /// </summary>
    /// <param name="Protocol">TCP or UDP.</param>
    /// <param name="Ports">A single port or range as stated by the rule (e.g. "5900-5904").</param>
    /// <param name="RuleName">Name of the rule - shows what the port belongs to.</param>
    /// <param name="AnyProgram">
    /// The rule applies to <b>every</b> program. Only such ports can be used
    /// without a new rule: a rule bound to a specific program does not help
    /// another application.
    /// </param>
    public readonly record struct AllowedInboundPort(
        string Protocol,
        string Ports,
        string RuleName,
        bool AnyProgram);

    /// <summary>Result of an attempt to create or remove a rule.</summary>
    /// <param name="Success">The change succeeded.</param>
    /// <param name="Message">Plain-language message for display - also on success.</param>
    public readonly record struct FirewallChangeResult(bool Success, string Message);

    /// <summary>
    /// Access to the local firewall: reads which inbound ports are allowed and -
    /// with elevated privileges - creates a dedicated rule.
    /// <para>
    /// The purpose is the listening port of the main scanner. Without privileges,
    /// a port that is already open can be chosen; with administrator rights, the
    /// desired port can be opened directly. The user interface supports both.
    /// </para>
    /// <para>
    /// Only a rule <b>for this application</b> is ever created, with a
    /// recognizable name and for exactly one port. Nothing is opened broadly,
    /// and existing rules are not touched.
    /// </para>
    /// </summary>
    public interface IFirewallInspector
    {
        /// <summary>Whether firewall rules can be read on this platform at all.</summary>
        bool IsSupported { get; }

        /// <summary>
        /// All active allow rules for inbound connections with a specific port.
        /// Empty if nothing could be read.
        /// </summary>
        IReadOnlyList<AllowedInboundPort> ReadAllowedInbound();

        /// <summary>
        /// Whether a rule may be created - that is, whether the application runs
        /// with elevated privileges.
        /// </summary>
        bool CanCreateRule { get; }

        /// <summary>
        /// Creates an inbound allow rule for this application on the given TCP
        /// port. If the rule already exists, it is moved to the new port instead
        /// of creating a second one.
        /// </summary>
        /// <param name="port">The TCP port to allow.</param>
        /// <param name="ruleName">The name of the rule to create or update.</param>
        /// <returns>Whether the change succeeded, with a message for display.</returns>
        FirewallChangeResult AllowInboundTcp(int port, string ruleName);

        /// <summary>Removes a previously created rule.</summary>
        /// <param name="ruleName">The name of the rule to remove.</param>
        /// <returns>Whether the change succeeded, with a message for display.</returns>
        FirewallChangeResult RemoveRule(string ruleName);
    }

    /// <summary>Used when no implementation is available - reports that the operation is not supported.</summary>
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
