using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// Liest und schreibt Nachrichten auf einem Datenstrom.
    /// <para>
    /// Rahmen: 4 Byte Laenge (big-endian), dann die Nutzlast. Das oberste Bit
    /// der Laenge sagt, ob gepackt wurde - deshalb bleiben 31 Bit fuer die
    /// Groesse, weit mehr als die Obergrenze unten braucht.
    /// </para>
    /// <para>
    /// Warum ueberhaupt eine Laengenangabe: TCP kennt keine Nachrichten,
    /// sondern nur einen Strom von Bytes. Ohne Rahmen kaeme beim Lesen mal ein
    /// halbes und mal anderthalb JSON-Dokumente an.
    /// </para>
    /// </summary>
    public sealed class MessageChannel(Stream stream)
    {
        /// <summary>Ab dieser Groesse wird gepackt. Darunter kostet es mehr, als es bringt.</summary>
        private const int CompressAbove = 4 * 1024;

        /// <summary>
        /// Obergrenze je Nachricht. Schuetzt vor einer kaputten oder
        /// boesartigen Laengenangabe, die sonst den Speicher raeumen wuerde.
        /// 32 MiB reichen fuer ein vollstaendiges Ergebnis mit Reserve.
        /// </summary>
        public const int MaxMessageBytes = 32 * 1024 * 1024;

        private const uint CompressedFlag = 0x8000_0000;

        private static readonly JsonSerializerOptions Options = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private readonly Stream _stream = stream ?? throw new ArgumentNullException(nameof(stream));

        // Schreiben wird gebuendelt: zwei Seiten koennen gleichzeitig senden
        // wollen (etwa ein Ping waehrend eines Ergebnisses), und ineinander
        // geschachtelte Rahmen waeren nicht mehr zu entwirren.
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        public async Task SendAsync(SatelliteMessage message, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(message);

            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(message, Options);
            bool compress = payload.Length >= CompressAbove;

            if (compress)
            {
                using MemoryStream buffer = new();
                using (GZipStream gzip = new(buffer, CompressionLevel.Fastest, leaveOpen: true))
                {
                    await gzip.WriteAsync(payload, token);
                }
                payload = buffer.ToArray();
            }

            if (payload.Length > MaxMessageBytes)
            {
                throw new InvalidOperationException(
                    $"Message of {payload.Length} bytes exceeds the limit of {MaxMessageBytes}.");
            }

            byte[] header = new byte[4];
            uint value = (uint)payload.Length | (compress ? CompressedFlag : 0);
            BinaryPrimitives.WriteUInt32BigEndian(header, value);

            await _writeLock.WaitAsync(token);
            try
            {
                await _stream.WriteAsync(header, token);
                await _stream.WriteAsync(payload, token);
                await _stream.FlushAsync(token);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        /// <summary>
        /// Liest die naechste Nachricht. Gibt <c>null</c> zurueck, wenn die
        /// Gegenstelle sauber aufgelegt hat.
        /// </summary>
        public async Task<SatelliteMessage?> ReceiveAsync(CancellationToken token)
        {
            byte[] header = new byte[4];
            if (!await ReadExactlyAsync(header, token)) return null;

            uint value = BinaryPrimitives.ReadUInt32BigEndian(header);
            bool compressed = (value & CompressedFlag) != 0;
            int length = (int)(value & ~CompressedFlag);

            if (length is < 0 or > MaxMessageBytes)
            {
                throw new InvalidDataException(
                    $"Announced message length of {length} bytes is out of range.");
            }

            byte[] payload = new byte[length];
            if (!await ReadExactlyAsync(payload, token))
            {
                throw new EndOfStreamException("Connection closed in the middle of a message.");
            }

            if (compressed)
            {
                using MemoryStream packed = new(payload);
                using GZipStream gzip = new(packed, CompressionMode.Decompress);
                using MemoryStream plain = new();
                await gzip.CopyToAsync(plain, token);
                payload = plain.ToArray();
            }

            return JsonSerializer.Deserialize<SatelliteMessage>(payload, Options);
        }

        /// <summary>
        /// Fuellt den Puffer ganz. Ein einzelnes Read liefert unter Umstaenden
        /// weniger, als angefordert wurde - das ist bei TCP der Normalfall und
        /// nicht der Fehlerfall.
        /// </summary>
        private async Task<bool> ReadExactlyAsync(byte[] buffer, CancellationToken token)
        {
            int read = 0;
            while (read < buffer.Length)
            {
                int chunk = await _stream.ReadAsync(buffer.AsMemory(read), token);
                if (chunk == 0) return false;
                read += chunk;
            }
            return true;
        }

        /// <summary>Ein neuer, zufaelliger Bezeichner fuer einen Auftrag.</summary>
        public static string NewJobId() => Guid.NewGuid().ToString("N")[..12];
    }
}
