// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Modbus TCP. Controllers of this kind tolerate little, so detection uses
    /// one connection and one request.
    /// </summary>
    public sealed class ModBusProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.ModBus;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [502];

        /// <summary>Read Holding Registers (0x03), unit 1, register 0, count 1.</summary>
        public override byte[] Hello => new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 };

        /// <summary>Matches an MBAP header with protocol ID 0 and a valid function or exception code.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            if (service == ServiceType.ModBus)
            {
                // The Modbus TCP (MBAP) header is 7 bytes; the function code is the
                // first byte after it, index 7, which can only be read if the answer
                // is at least 8 bytes long. With ">= 7", a 7-byte answer would throw
                // an IndexOutOfRangeException and count as an error instead of
                // "not Modbus".
                // [0-1] Transaction Identifier (2 bytes)
                // [2-3] Protocol Identifier (always 0x00 0x00 for Modbus TCP)
                // [4-5] Length Field (length of the following data)
                // [6]   Unit Identifier
                // [7]   Function Code
                if (response.Length >= 8)
                {
                    // Check the protocol identifier (must be 0x00 0x00 for Modbus TCP)
                    bool isModbusTcp = response[2] == 0x00 && response[3] == 0x00;

                    // Check the function code: the common Modbus function codes 0x01 to 0x10
                    // (the specification defines further ones, e.g. 0x17 and 0x2B, that are not accepted here)
                    // Examples:
                    // 0x01 - Read Coils
                    // 0x02 - Read Discrete Inputs
                    // 0x03 - Read Holding Registers
                    // 0x04 - Read Input Registers
                    // 0x05 - Write Single Coil
                    // 0x06 - Write Single Register
                    // 0x10 - Write Multiple Registers
                    //
                    // An exception response carries the same function code with
                    // the most significant bit set, i.e. 0x81-0x90, for example
                    // when the requested register does not exist on this device.
                    // That is still a Modbus answer and a match: the device
                    // understood and answered, just with "no" instead of values.
                    byte functionCode = response[7];
                    bool validFunctionCode = functionCode is >= 0x01 and <= 0x10 or >= 0x81 and <= 0x90;

                    // Modbus TCP is detected when both protocol and function code match
                    if (isModbusTcp && validFunctionCode)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// First the common detection, then the request for the device
        /// identification.
        /// <para>
        /// Detection alone decides the finding. Its answer, however, contains
        /// only a register value and says nothing about who is answering. A
        /// device that reveals it does so on function code 0x2B with MEI type
        /// 0x0E ("Read Device Identification", Modbus Application Protocol
        /// Specification V1.1b3, section 6.21): vendor, product code, revision.
        /// </para>
        /// <para>
        /// This function is optional. A device that does not know the code
        /// answers with 0xAB and exception code 1 ("illegal function"): a valid
        /// Modbus answer and not an error, just no information. The finding
        /// then stays as it is.
        /// </para>
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            if (portResult.Status != PortStatus.IsRunning) return portResult;

            string? info = null;

            try
            {
                // First the two standard ways, in order of how much they yield:
                // 0x2B returns individual named fields, 0x11 only a string the
                // vendor defines freely.
                info = await ReadDeviceIdentificationAsync(context, address, port, token);
                info ??= await ReadServerIdAsync(context, address, port, token);

                // Finally the vendor-specific way. Not every device supports
                // the standard ones: WAGO answers both with "illegal function"
                // but stores the same information in its own holding
                // registers.
                info ??= await ReadWagoIdentificationAsync(context, address, port, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // The finding is already established; the identification is extra.
            }

            portResult.PortLog = info ?? "Unit ID 1 answered, device identification not supported.";

            return portResult;
        }

        /// <summary>
        /// Requests the basic device identification and reads the objects from
        /// the answer. <c>null</c> if the device does not know the function.
        /// </summary>
        private static async Task<string?> ReadDeviceIdentificationAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // MBAP header: transaction 2, protocol 0, length 5, unit 1.
            // Then: 0x2B function code, 0x0E MEI type, 0x01 basic device
            // identification, 0x00 first object.
            byte[] request = [0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00];

            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs);

            await stream.WriteAsync(request, timeout.Token);

            byte[] buffer = new byte[512];
            int read = await stream.ReadAsync(buffer, timeout.Token);
            if (read <= 0) return null;

            return ParseDeviceIdentification(buffer[..read]);
        }

        /// <summary>
        /// Layout of the answer: seven bytes MBAP header, then function code,
        /// MEI type, read device ID code, conformity level, "more follows",
        /// next object ID, number of objects, and then per object its ID,
        /// length and text.
        /// </summary>
        private static string? ParseDeviceIdentification(byte[] response)
        {
            const int HeaderLength = 7;

            // Too short, or no answer to this function code at all.
            if (response.Length < HeaderLength + 2) return null;

            // 0xAB is 0x2B with the most significant bit set: the device does not
            // know the function.
            if (response[HeaderLength] != 0x2B) return null;
            if (response.Length < HeaderLength + 8) return null;

            int count = response[HeaderLength + 6];
            int p = HeaderLength + 7;

            List<string> lines = [];

            for (int i = 0; i < count && p + 1 < response.Length; i++)
            {
                int objectId = response[p];
                int length = response[p + 1];
                p += 2;

                if (p + length > response.Length) break;

                string value = Encoding.ASCII.GetString(response, p, length).Trim();
                p += length;

                if (value.Length == 0) continue;

                lines.Add($"{ObjectName(objectId)}: {value}");
            }

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// Function code 0x11 "Report Server ID" (Modbus Application Protocol
        /// Specification V1.1b3, section 6.13), the second standard way.
        /// <para>
        /// The content of the answer is defined by the vendor: usually a name
        /// in plain text, sometimes only a number. Therefore only the printable
        /// part is taken and everything from the first control character on is
        /// discarded.
        /// </para>
        /// <para>
        /// <c>null</c> if the device does not know the function; it then answers
        /// with 0x91 and an exception code. None of the devices tested so far
        /// supports it; it is included because it is standardised and costs a
        /// single request.
        /// </para>
        /// </summary>
        private static async Task<string?> ReadServerIdAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // MBAP header: transaction 3, protocol 0, length 2, unit 1, then the
            // function code alone; the request has no further data.
            byte[] request = [0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x11];

            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs);

            await stream.WriteAsync(request, timeout.Token);

            byte[] buffer = new byte[512];
            int read = await stream.ReadAsync(buffer, timeout.Token);

            const int HeaderLength = 7;

            if (read < HeaderLength + 2) return null;
            if (buffer[HeaderLength] != 0x11) return null;   // 0x91 would be the rejection

            int count = buffer[HeaderLength + 1];
            if (count <= 0 || HeaderLength + 2 + count > read) return null;

            var text = new StringBuilder();

            for (int i = HeaderLength + 2; i < HeaderLength + 2 + count; i++)
            {
                if (buffer[i] is >= 0x20 and <= 0x7E) text.Append((char)buffer[i]);
                else break;
            }

            string id = text.ToString().Trim();
            return id.Length >= 2 ? $"Server ID: {id}" : null;
        }

        /// <summary>
        /// The identification of a WAGO controller from its holding registers.
        /// <para>
        /// WAGO does not answer the standard function code 0x2B but stores the
        /// information from register 0x2010 on, readable without login, while
        /// the web interface of the same device returns only 401 without
        /// credentials.
        /// </para>
        /// <para>
        /// The text has its bytes swapped per register: "AWOG" becomes "WAGO".
        /// </para>
        /// <para>
        /// The short description doubles as the safeguard: only if it says
        /// "WAGO" do the other registers count as identification. At these
        /// addresses another vendor's device may hold anything, process values
        /// for example, and these must not pass as a device name.
        /// </para>
        /// </summary>
        private static async Task<string?> ReadWagoIdentificationAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs);
            CancellationToken read = timeout.Token;

            string? description = SwappedText(await ReadHoldingAsync(stream, 0x2020, 16, read));

            if (description is null ||
                !description.StartsWith("WAGO", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            List<string> lines = [$"Device: {description}"];

            int? series = await ReadWordAsync(stream, 0x2011, read);
            int? item = await ReadWordAsync(stream, 0x2012, read);

            if (series is not null && item is not null)
            {
                lines.Add($"Order number: {series}-{item}");
            }

            int? major = await ReadWordAsync(stream, 0x2013, read);
            int? minor = await ReadWordAsync(stream, 0x2014, read);

            if (major is not null && minor is not null)
            {
                lines.Add($"Firmware: V{major}.{minor}");
            }

            string? date = SwappedText(await ReadHoldingAsync(stream, 0x2022, 8, read));
            if (!string.IsNullOrWhiteSpace(date)) lines.Add($"Firmware date: {date}");

            return string.Join(Environment.NewLine, lines);
        }

        /// <summary>A single holding register as a number.</summary>
        private static async Task<int?> ReadWordAsync(
            NetworkStream stream, int register, CancellationToken token)
        {
            byte[]? data = await ReadHoldingAsync(stream, register, 1, token);
            return data is { Length: >= 2 } ? (data[0] << 8) | data[1] : null;
        }

        /// <summary>
        /// Reads holding registers with function code 0x03 and returns the data
        /// part only. <c>null</c> if the device answers with an exception, for
        /// example because it does not know the address.
        /// </summary>
        private static async Task<byte[]?> ReadHoldingAsync(
            NetworkStream stream, int register, int count, CancellationToken token)
        {
            byte[] request =
            [
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03,
                (byte)(register >> 8), (byte)(register & 0xFF),
                (byte)(count >> 8), (byte)(count & 0xFF)
            ];

            await stream.WriteAsync(request, token);

            byte[] buffer = new byte[512];
            int read = await stream.ReadAsync(buffer, token);

            // Header, function code and byte count must be present, and the
            // function code must not carry the exception bit.
            if (read < 9 || buffer[7] != 0x03) return null;

            int length = buffer[8];
            if (length <= 0 || 9 + length > read) return null;

            return buffer[9..(9 + length)];
        }

        /// <summary>
        /// Text from registers in which the two bytes of each register are
        /// swapped. Non-printable characters end it.
        /// </summary>
        private static string? SwappedText(byte[]? data)
        {
            if (data is null || data.Length < 2) return null;

            var text = new StringBuilder();

            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                foreach (byte b in (byte[])[data[i + 1], data[i]])
                {
                    if (b is >= 0x20 and <= 0x7E) text.Append((char)b);
                    else return Trimmed(text);
                }
            }

            return Trimmed(text);
        }

        private static string? Trimmed(StringBuilder text)
        {
            string result = text.ToString().Trim();
            return result.Length >= 2 ? result : null;
        }

        /// <summary>The object IDs of the device identification as assigned by the Modbus specification.</summary>
        private static string ObjectName(int objectId) => objectId switch
        {
            0x00 => "Vendor",
            0x01 => "Product code",
            0x02 => "Revision",
            0x03 => "Vendor URL",
            0x04 => "Product name",
            0x05 => "Model name",
            0x06 => "Application name",
            _ => $"Object 0x{objectId:X2}"
        };
    }
}
