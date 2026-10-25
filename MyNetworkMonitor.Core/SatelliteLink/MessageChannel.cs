// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// Reads and writes messages on a stream.
    /// <para>
    /// Frame: 4-byte length (big-endian), followed by the payload. The top bit
    /// of the length indicates whether the payload is gzip-compressed, which
    /// leaves 31 bits for the size, far more than the limit below needs.
    /// </para>
    /// <para>
    /// Why a length prefix: TCP has no messages, only a stream of bytes.
    /// Without framing, a read could return half a JSON document or one and a
    /// half.
    /// </para>
    /// </summary>
    /// <param name="stream">The connected stream (TCP or named pipe).</param>
    public sealed class MessageChannel(Stream stream)
    {
        /// <summary>Payloads of at least this size are compressed. Below it, compression costs more than it saves.</summary>
        private const int CompressAbove = 4 * 1024;

        /// <summary>
        /// Upper limit per message. Protects against a corrupt or malicious
        /// length prefix that would otherwise exhaust memory. 32 MiB holds a
        /// complete result with room to spare.
        /// </summary>
        public const int MaxMessageBytes = 32 * 1024 * 1024;

        /// <summary>
        /// Upper limit per message after decompression. The frame limit alone
        /// does not bound memory: a few hundred kilobytes of gzip can expand to
        /// gigabytes (a "gzip bomb"). JSON results compress by roughly a factor
        /// of ten, so four times the frame limit leaves ample room for real
        /// messages. See docs/FEHLERGEDAECHTNIS.md, No. 20.
        /// </summary>
        public const int MaxPlainBytes = 4 * MaxMessageBytes;

        private const uint CompressedFlag = 0x8000_0000;

        private static readonly JsonSerializerOptions Options = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private readonly Stream _stream = stream ?? throw new ArgumentNullException(nameof(stream));

        // Writes are serialized: two senders may write at the same time (for
        // example a ping during a result), and interleaved frames could not be
        // separated again.
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        /// <summary>Serializes a message, compresses it if worthwhile, and writes it as one frame.</summary>
        /// <param name="message">The message to send.</param>
        /// <param name="token">Cancels the write.</param>
        /// <exception cref="ArgumentNullException"><paramref name="message"/> is null.</exception>
        /// <exception cref="InvalidOperationException">The payload exceeds <see cref="MaxPlainBytes"/>, or <see cref="MaxMessageBytes"/> after compression.</exception>
        public async Task SendAsync(SatelliteMessage message, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(message);

            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(message, Options);

            // The receiver rejects anything larger; failing here names the cause.
            if (payload.Length > MaxPlainBytes)
            {
                throw new InvalidOperationException(
                    $"Message of {payload.Length} bytes exceeds the limit of {MaxPlainBytes}.");
            }

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
        /// Reads the next message.
        /// </summary>
        /// <param name="token">Cancels the read.</param>
        /// <returns>The message, or <c>null</c> if the peer closed the connection cleanly between two messages.</returns>
        /// <exception cref="InvalidDataException">The announced length is out of range, or the decompressed payload exceeds <see cref="MaxPlainBytes"/>.</exception>
        /// <exception cref="EndOfStreamException">The connection closed in the middle of a message.</exception>
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

            if (compressed) payload = await DecompressAsync(payload, token);

            return JsonSerializer.Deserialize<SatelliteMessage>(payload, Options);
        }

        /// <summary>
        /// Unpacks a gzip payload, stopping as soon as it grows beyond
        /// <see cref="MaxPlainBytes"/> instead of after it has filled memory.
        /// </summary>
        private static async Task<byte[]> DecompressAsync(byte[] packed, CancellationToken token)
        {
            using MemoryStream source = new(packed);
            using GZipStream gzip = new(source, CompressionMode.Decompress);
            using MemoryStream plain = new();
            byte[] chunk = new byte[81920];
            int read;
            while ((read = await gzip.ReadAsync(chunk, token)) > 0)
            {
                if (plain.Length + read > MaxPlainBytes)
                {
                    throw new InvalidDataException(
                        $"Decompressed message exceeds the limit of {MaxPlainBytes} bytes.");
                }
                plain.Write(chunk, 0, read);
            }
            return plain.ToArray();
        }

        /// <summary>
        /// Fills the buffer completely. A single Read may return less than
        /// requested; with TCP that is the normal case, not an error.
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

        /// <summary>Creates a new random identifier for a job.</summary>
        /// <returns>A 12-character hexadecimal identifier.</returns>
        public static string NewJobId() => Guid.NewGuid().ToString("N")[..12];
    }
}
