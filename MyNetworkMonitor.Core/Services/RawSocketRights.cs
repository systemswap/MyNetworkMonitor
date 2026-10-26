// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Whether the program may open raw sockets under Linux, which the IPv6 methods that listen (Router Advertisement,
    /// MLD) need, and how to grant it. Shown by the system check and by the methods themselves when they cannot listen.
    /// </summary>
    /// <remarks>
    /// The right is the capability <c>CAP_NET_RAW</c> (capabilities(7)) or running as root. It is granted to the program
    /// file with <c>setcap</c>. An AppImage cannot carry it: it runs from a FUSE mount, where file capabilities have no
    /// effect; the program has to be extracted first. See docs/FEHLERGEDAECHTNIS.md, No. 27.
    /// </remarks>
    public static class RawSocketRights
    {
        /// <summary>Key for "don't show again" in the system check.</summary>
        public const string Id = "cap_net_raw";

        /// <summary>Bit of CAP_NET_RAW in the capability sets (linux/capability.h).</summary>
        private const int CapNetRaw = 13;

        /// <summary>Whether the running process may open raw sockets. Always true outside Linux, where this check does not apply.</summary>
        public static bool Present
        {
            get
            {
                if (!OperatingSystem.IsLinux()) return true;
                if (Environment.IsPrivilegedProcess) return true;
                try
                {
                    return HasEffectiveCapability(File.ReadLines("/proc/self/status"), CapNetRaw);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    return false;
                }
            }
        }

        /// <summary>The path of the AppImage the program runs from, or null (set by the AppImage runtime as <c>APPIMAGE</c>).</summary>
        public static string? AppImagePath
        {
            get
            {
                string? path = Environment.GetEnvironmentVariable("APPIMAGE");
                return string.IsNullOrWhiteSpace(path) ? null : path;
            }
        }

        /// <summary>
        /// Whether the effective capability set in the lines of <c>/proc/&lt;pid&gt;/status</c> contains a capability.
        /// </summary>
        /// <param name="statusLines">The lines of the status file.</param>
        /// <param name="bit">The capability number.</param>
        /// <returns>True if the line <c>CapEff</c> has the bit set.</returns>
        public static bool HasEffectiveCapability(IEnumerable<string> statusLines, int bit)
        {
            foreach (string line in statusLines)
            {
                if (!line.StartsWith("CapEff:", StringComparison.Ordinal)) continue;
                return ulong.TryParse(line["CapEff:".Length..].Trim(), System.Globalization.NumberStyles.HexNumber, null, out ulong set)
                    && (set & (1UL << bit)) != 0;
            }
            return false;
        }

        /// <summary>The command that grants the right, for the way the program runs.</summary>
        /// <param name="executablePath">The program file (<see cref="Environment.ProcessPath"/>).</param>
        /// <param name="appImagePath">The AppImage, if the program runs from one (<see cref="AppImagePath"/>).</param>
        /// <returns>
        /// For a plain program file <c>sudo setcap cap_net_raw+ep '&lt;file&gt;'</c>; for an AppImage the extraction next
        /// to it followed by setcap on the extracted program.
        /// </returns>
        public static string GrantCommand(string executablePath, string? appImagePath)
        {
            if (appImagePath is null) return $"sudo setcap cap_net_raw+ep {Quote(executablePath)}";

            // Cut at the last '/' instead of Path.GetDirectoryName: that turns '/' into '\' when the tests run on Windows
            int slash = appImagePath.LastIndexOf('/');
            string folder = slash > 0 ? appImagePath[..slash] : slash == 0 ? "/" : ".";
            return $"cd {Quote(folder)} && {Quote(appImagePath)} --appimage-extract > /dev/null && " +
                   $"sudo setcap cap_net_raw+ep squashfs-root/usr/bin/{Path.GetFileName(executablePath)}";
        }

        /// <summary>The explanation that goes with <see cref="GrantCommand"/> (English, shown in the user interface).</summary>
        /// <param name="appImagePath">The AppImage, if the program runs from one.</param>
        /// <returns>One or two sentences.</returns>
        public static string GrantHint(string? appImagePath) => appImagePath is null
            ? "Start the program with sudo, or grant the right once with this command (setcap is in the package libcap2-bin on Debian/Ubuntu and libcap on Fedora):"
            : "An AppImage cannot carry this right. This command unpacks it next to the AppImage and grants the right to the unpacked program; start it with squashfs-root/AppRun from then on:";

        /// <summary>Single quotes for the shell; a quote inside is closed, escaped and reopened.</summary>
        private static string Quote(string text) => "'" + text.Replace("'", "'\\''") + "'";
    }
}
