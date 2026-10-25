namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Estimates the operating system of the target from the remaining TTL of a
    /// ping reply.
    /// <para>
    /// The idea: every operating system sets a typical initial TTL when
    /// sending, and every router on the way back subtracts exactly one. Rounded
    /// up to the next common initial value, the packet thus reveals its origin -
    /// and the number of hops along with it.
    /// </para>
    /// <para>
    /// Deliberately labeled as a <b>guess</b> and not as a determination. The
    /// initial TTL can be changed, and a target behind a NAT gateway can carry
    /// a different one. For the question "what is out there at all" it is still
    /// sufficient, and it costs not a single extra packet.
    /// </para>
    /// </summary>
    public static class TtlFingerprint
    {
        /// <summary>
        /// The common initial values. 64 covers Linux, macOS, Android and the vast
        /// majority of embedded devices; 128 is Windows; 255 is used by network
        /// devices and some older Unix systems.
        /// </summary>
        private static readonly (int Initial, string Guess)[] Known =
        [
            (64, "Linux / Unix / Android"),
            (128, "Windows"),
            (255, "Network device")
        ];

        /// <summary>
        /// How far the remaining TTL may at most lie below the initial value for
        /// that initial value to still count as the right one.
        /// <para>
        /// 32 hops are excessive on the local network this is about - but a
        /// larger span would start pulling 128 into the 255 bucket and thus
        /// declare every Windows machine behind enough routers a switch.
        /// </para>
        /// </summary>
        private const int MaxHops = 32;

        /// <summary>
        /// The guessed operating system, or <c>null</c> if the TTL matches none
        /// of the known initial values.
        /// </summary>
        /// <param name="ttl">The remaining TTL of the reply.</param>
        public static string? Guess(int ttl)
        {
            if (ttl <= 0) return null;

            foreach ((int initial, string guess) in Known)
            {
                if (ttl <= initial && ttl > initial - MaxHops) return guess;
            }

            return null;
        }

        /// <summary>
        /// The number of hops on the way back, or <c>null</c> if the initial value
        /// cannot be determined. Zero hops means the target is on the same
        /// segment.
        /// </summary>
        /// <param name="ttl">The remaining TTL of the reply.</param>
        public static int? Hops(int ttl)
        {
            if (ttl <= 0) return null;

            foreach ((int initial, _) in Known)
            {
                if (ttl <= initial && ttl > initial - MaxHops) return initial - ttl;
            }

            return null;
        }

        /// <summary>
        /// The finished line for the detail view, for example
        /// <c>"Windows (TTL 128, same segment)"</c>. <c>null</c> if nothing was
        /// measured - then no line is shown either.
        /// </summary>
        /// <param name="ttl">The remaining TTL of the reply.</param>
        public static string? Describe(int ttl)
        {
            string? guess = Guess(ttl);
            if (guess is null) return null;

            int hops = Hops(ttl) ?? 0;

            string distance = hops == 0
                ? "same segment"
                : hops == 1 ? "1 hop away" : $"{hops} hops away";

            return $"{guess} (TTL {ttl}, {distance})";
        }
    }
}
