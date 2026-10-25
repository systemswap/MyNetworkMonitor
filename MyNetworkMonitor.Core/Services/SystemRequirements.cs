namespace MyNetworkMonitor.Core.Services
{
    /// <summary>Package-manager family whose install command is shown first.</summary>
    public enum PackageFamily
    {
        /// <summary>Not recognised: both commands are shown in the default order.</summary>
        Unknown,

        /// <summary>Debian, Ubuntu and derivatives (apt).</summary>
        Debian,

        /// <summary>Fedora, RHEL and derivatives (dnf).</summary>
        Fedora,
    }

    /// <summary>One program of the system that MyNetworkMonitor calls.</summary>
    /// <param name="Id">Stable key, used for "don't show again" in the settings.</param>
    /// <param name="Command">Name of the program on the PATH.</param>
    /// <param name="Purpose">What it is used for (English, displayed in the UI).</param>
    /// <param name="WithoutIt">What happens if it is missing (English, displayed in the UI).</param>
    /// <param name="Required">True if a main function does not work without it; optional ones are only a hint.</param>
    /// <param name="DebianPackage">Package on Debian and Ubuntu.</param>
    /// <param name="FedoraPackage">Package on Fedora.</param>
    public sealed record SystemRequirement(
        string Id, string Command, string Purpose, string WithoutIt, bool Required, string DebianPackage, string FedoraPackage);

    /// <summary>Result of checking one requirement.</summary>
    /// <param name="Requirement">The requirement.</param>
    /// <param name="Present">Whether the program was found.</param>
    public sealed record SystemCheckResult(SystemRequirement Requirement, bool Present);

    /// <summary>
    /// The programs of the system that MyNetworkMonitor needs, in one place, and the check whether they are there. The
    /// program never installs anything itself; it shows the install commands for Debian/Ubuntu and Fedora (the running
    /// system first) to copy.
    /// </summary>
    /// <remarks>
    /// Only Linux needs anything: on Windows all lookups go through the system API. The check reads only the PATH and
    /// <c>/etc/os-release</c> – fast, without network access.
    /// </remarks>
    public static class SystemRequirements
    {
        /// <summary>
        /// The programs called under Linux. Package names verified for Debian 13 via <c>dpkg -S</c> (packages.debian.org)
        /// and for Fedora on packages.fedoraproject.org (file lists of the packages).
        /// </summary>
        public static IReadOnlyList<SystemRequirement> Linux { get; } =
        [
            new("ip", "ip",
                "Reads the ARP table, the IPv6 neighbour table and the routes of the system.",
                "No MAC addresses, vendors or IPv6 neighbours, and no default gateway for name lookups.",
                Required: true, DebianPackage: "iproute2", FedoraPackage: "iproute"),
            new("ping", "ping",
                "Ping without special rights: .NET uses the system's ping when the program may not send ICMP itself.",
                "The ping scan finds no devices unless the program runs with raw-socket rights.",
                Required: true, DebianPackage: "iputils-ping", FedoraPackage: "iputils"),
            new("nmcli", "nmcli",
                "Shows the Wi-Fi network the computer is connected to.",
                "The Wi-Fi details stay empty; everything else works.",
                Required: false, DebianPackage: "network-manager", FedoraPackage: "NetworkManager"),
            new("xdg-open", "xdg-open",
                "Opens the 3D network view in the web browser.",
                "The 3D view cannot be opened; the scan results are not affected.",
                Required: false, DebianPackage: "xdg-utils", FedoraPackage: "xdg-utils"),
        ];

        /// <summary>The package family of the running system, read from <c>/etc/os-release</c>.</summary>
        public static PackageFamily CurrentFamily { get; } = DetectFamily();

        /// <summary>Checks all requirements of the running system.</summary>
        /// <returns>One result per requirement; empty on Windows and macOS.</returns>
        public static IReadOnlyList<SystemCheckResult> Check() =>
            OperatingSystem.IsLinux()
                ? [.. Linux.Select(r => new SystemCheckResult(r, IsOnPath(r.Command, Environment.GetEnvironmentVariable("PATH"))))]
                : [];

        /// <summary>Whether an executable file of this name lies in one of the folders of <paramref name="path"/>.</summary>
        /// <param name="command">Program name without folder.</param>
        /// <param name="path">The PATH variable (folders separated by ':').</param>
        /// <returns>True if found and executable.</returns>
        public static bool IsOnPath(string command, string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            foreach (string folder in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string candidate = Path.Combine(folder, command);
                    if (!File.Exists(candidate)) continue;
                    if (OperatingSystem.IsWindows()) return true;
                    UnixFileMode mode = File.GetUnixFileMode(candidate);
                    if ((mode & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0) return true;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    // An unreadable folder in the PATH is no reason to fail; try the next one.
                }
            }
            return false;
        }

        /// <summary>The install command for Debian/Ubuntu.</summary>
        /// <param name="missing">The missing requirements.</param>
        /// <returns>For example <c>sudo apt install iproute2 xdg-utils</c>.</returns>
        public static string DebianCommand(IEnumerable<SystemRequirement> missing) =>
            "sudo apt install " + string.Join(' ', missing.Select(r => r.DebianPackage).Distinct());

        /// <summary>The install command for Fedora.</summary>
        /// <param name="missing">The missing requirements.</param>
        /// <returns>For example <c>sudo dnf install iproute xdg-utils</c>.</returns>
        public static string FedoraCommand(IEnumerable<SystemRequirement> missing) =>
            "sudo dnf install " + string.Join(' ', missing.Select(r => r.FedoraPackage).Distinct());

        /// <summary>Classifies the lines of an os-release file by <c>ID</c> and <c>ID_LIKE</c>.</summary>
        /// <param name="osReleaseLines">The lines of <c>/etc/os-release</c>.</param>
        /// <returns>The family whose packages the system uses.</returns>
        public static PackageFamily Classify(IEnumerable<string> osReleaseLines)
        {
            foreach (string line in osReleaseLines)
            {
                int separator = line.IndexOf('=');
                if (separator <= 0) continue;
                string key = line[..separator].Trim();
                if (key is not ("ID" or "ID_LIKE")) continue;
                foreach (string id in line[(separator + 1)..].Trim().Trim('"', '\'').ToLowerInvariant()
                             .Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (id is "debian" or "ubuntu") return PackageFamily.Debian;
                    if (id is "fedora" or "rhel" or "centos") return PackageFamily.Fedora;
                }
            }
            return PackageFamily.Unknown;
        }

        private static PackageFamily DetectFamily()
        {
            if (!OperatingSystem.IsLinux()) return PackageFamily.Unknown;
            foreach (string file in (string[])["/etc/os-release", "/usr/lib/os-release"])
            {
                try
                {
                    if (File.Exists(file)) return Classify(File.ReadLines(file));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    // Unknown system: both commands are shown.
                }
            }
            return PackageFamily.Unknown;
        }
    }
}
