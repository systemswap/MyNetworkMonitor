using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// Der eigene Schluessel dieser Instanz - Grundlage der Anmeldung nach
    /// SATELLIT.md, Abschnitt 4.
    /// <para>
    /// Er entsteht beim ersten Start von selbst und wird neben den
    /// Einstellungen abgelegt. Genau darum muss beim Installieren nichts
    /// hinterlegt oder kopiert werden: die Gegenstellen lernen den
    /// Fingerabdruck ueber die Leitung kennen, und ein Mensch gibt ihn einmal
    /// frei.
    /// </para>
    /// </summary>
    public static class SatelliteIdentity
    {
        public const string DefaultFileName = "identity.pfx";

        /// <summary>
        /// Gibt das eigene Zertifikat zurueck und legt es an, falls es noch
        /// keines gibt.
        /// </summary>
        public static X509Certificate2 GetOrCreate(string settingsFolder, string subjectName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(settingsFolder);

            string path = Path.Combine(settingsFolder, DefaultFileName);

            if (File.Exists(path))
            {
                try
                {
                    return Load(path);
                }
                catch (CryptographicException)
                {
                    // Unlesbar geworden - lieber ein neuer Schluessel als gar
                    // keine Verbindung. Die Gegenstellen melden dann einen
                    // geaenderten Fingerabdruck, und das ist die richtige
                    // Reaktion: es *ist* ein anderer Schluessel.
                    File.Delete(path);
                }
            }

            using RSA key = RSA.Create(2048);

            CertificateRequest request = new(
                $"CN={Sanitize(subjectName)}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));

            // Beide Rollen: dieselbe Anwendung ist einmal Lauscher und einmal
            // Verbinder, und beide Seiten weisen sich mit demselben Schluessel
            // aus.
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], critical: false));

            // Weit in die Zukunft: das Zertifikat ist kein Vertrauensanker,
            // sondern nur Traeger des Schluessels. Vertrauen entsteht durch die
            // Freigabe des Fingerabdrucks, nicht durch eine Laufzeit.
            using X509Certificate2 created = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(20));

            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            File.WriteAllBytes(path, created.Export(X509ContentType.Pfx));

            // Nicht das eben erzeugte Objekt zurueckgeben, sondern das neu
            // geladene: unter Windows braucht SslStream einen Schluessel, der
            // aus einer PFX stammt - ein frisch erzeugter laesst sich sonst
            // nicht zum Signieren verwenden.
            return Load(path);
        }

        private static X509Certificate2 Load(string path) =>
            X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(path), password: null, StorageFlags);

        /// <summary>
        /// Wie der private Schluessel beim Laden abgelegt wird.
        /// <para>
        /// Unter Windows ausdruecklich <b>nicht</b> <c>EphemeralKeySet</c>:
        /// Schannel kann mit einem fluechtigen Schluessel kein Zertifikat als
        /// Serverseite anbieten und bricht den Handschlag ab - "the platform
        /// does not support ephemeral keys". Der Fehler faellt nur auf, wenn
        /// wirklich eine Verbindung zustande kommen soll; er wurde beim
        /// Gegeneinanderlaufen von Lauscher und Verbinder entdeckt.
        /// </para>
        /// <para>
        /// Unter Linux ist der fluechtige Schluessel dagegen der richtige Weg:
        /// dort gibt es keinen Schluesselspeicher des Betriebssystems, in dem
        /// etwas zurueckbliebe.
        /// </para>
        /// </summary>
        private static X509KeyStorageFlags StorageFlags =>
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet
                : X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

        /// <summary>
        /// Der Fingerabdruck eines Zertifikats: SHA-256 ueber seine Rohform,
        /// in Zweierpaaren mit Doppelpunkten - so, wie man ihn vergleicht.
        /// </summary>
        public static string Fingerprint(X509Certificate2 certificate)
        {
            ArgumentNullException.ThrowIfNull(certificate);

            byte[] hash = SHA256.HashData(certificate.RawData);
            return Convert.ToHexString(hash);
        }

        /// <summary>Fuer die Anzeige: in Zweierpaaren, mit Doppelpunkten.</summary>
        public static string ForDisplay(string fingerprint) =>
            string.IsNullOrEmpty(fingerprint)
                ? string.Empty
                : string.Join(':', Enumerable.Range(0, fingerprint.Length / 2)
                                             .Select(i => fingerprint.Substring(i * 2, 2)));

        /// <summary>
        /// Macht aus einem Anzeigenamen etwas, das als Zertifikatsname
        /// durchgeht - Kommas und Gleichheitszeichen wuerden den Namen sonst
        /// zerlegen.
        /// </summary>
        private static string Sanitize(string name)
        {
            string cleaned = new([.. (name ?? string.Empty)
                .Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or ' ' or '.')]);

            return string.IsNullOrWhiteSpace(cleaned) ? "MyNetworkMonitor" : cleaned.Trim();
        }
    }
}
