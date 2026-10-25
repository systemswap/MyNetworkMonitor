using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// The own key of this instance, the basis of authentication according to
    /// SATELLIT.md, section 4.
    /// <para>
    /// It is created automatically on first start and stored next to the
    /// settings. That is why nothing has to be deployed or copied during
    /// installation: peers learn the fingerprint over the connection, and it
    /// is approved once by hand.
    /// </para>
    /// </summary>
    public static class SatelliteIdentity
    {
        /// <summary>File name of the certificate with the private key in the settings folder.</summary>
        public const string DefaultFileName = "identity.pfx";

        /// <summary>
        /// Returns the own certificate and creates it if none exists yet.
        /// </summary>
        /// <param name="settingsFolder">Folder that holds <see cref="DefaultFileName"/>.</param>
        /// <param name="subjectName">Display name used as the certificate subject when a new one is created.</param>
        /// <returns>The certificate including its private key.</returns>
        /// <exception cref="ArgumentException"><paramref name="settingsFolder"/> is null, empty or white space.</exception>
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
                    // Unreadable: a new key is better than no connection at
                    // all. Peers then report a changed fingerprint, which is the
                    // right reaction: it *is* a different key.
                    File.Delete(path);
                }
            }

            using RSA key = RSA.Create(2048);

            CertificateRequest request = new(
                $"CN={Sanitize(subjectName)}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));

            // Both roles (server and client authentication): the same
            // application acts as listener and as connector, and both sides
            // identify themselves with the same key.
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], critical: false));

            // Valid far into the future: the certificate is not a trust anchor,
            // only the carrier of the key. Trust comes from approving the
            // fingerprint, not from a validity period.
            using X509Certificate2 created = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(20));

            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            File.WriteAllBytes(path, created.Export(X509ContentType.Pfx));

            // Returns the reloaded object, not the one just created: on Windows,
            // SslStream needs a key that comes from a PFX; a freshly created key
            // cannot be used for signing there.
            return Load(path);
        }

        private static X509Certificate2 Load(string path) =>
            X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(path), password: null, StorageFlags);

        /// <summary>
        /// How the private key is stored when loading.
        /// <para>
        /// On Windows explicitly <b>not</b> <c>EphemeralKeySet</c>: Schannel
        /// cannot offer a certificate as the server side with an ephemeral key
        /// and aborts the handshake with "the platform does not support
        /// ephemeral keys". The error only shows when a connection between
        /// listener and connector is actually established.
        /// </para>
        /// <para>
        /// On Linux, the ephemeral key is the right choice: there is no key
        /// store of the operating system in which anything would be left behind.
        /// </para>
        /// </summary>
        private static X509KeyStorageFlags StorageFlags =>
            OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet
                : X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet;

        /// <summary>
        /// The fingerprint of a certificate: SHA-256 over its raw form, as
        /// upper-case hexadecimal without separators, the form used for
        /// comparison. <see cref="ForDisplay"/> formats it for display.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>64 hexadecimal characters.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
        public static string Fingerprint(X509Certificate2 certificate)
        {
            ArgumentNullException.ThrowIfNull(certificate);

            byte[] hash = SHA256.HashData(certificate.RawData);
            return Convert.ToHexString(hash);
        }

        /// <summary>Formats a fingerprint for display: in pairs, separated by colons.</summary>
        /// <param name="fingerprint">Fingerprint as returned by <see cref="Fingerprint"/>.</param>
        /// <returns>For example <c>AB:CD:…</c>, or an empty string for an empty input.</returns>
        public static string ForDisplay(string fingerprint) =>
            string.IsNullOrEmpty(fingerprint)
                ? string.Empty
                : string.Join(':', Enumerable.Range(0, fingerprint.Length / 2)
                                             .Select(i => fingerprint.Substring(i * 2, 2)));

        /// <summary>
        /// Turns a display name into something acceptable as a certificate
        /// subject; commas and equals signs would otherwise split the name.
        /// </summary>
        private static string Sanitize(string name)
        {
            string cleaned = new([.. (name ?? string.Empty)
                .Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or ' ' or '.')]);

            return string.IsNullOrWhiteSpace(cleaned) ? "MyNetworkMonitor" : cleaned.Trim();
        }
    }
}
