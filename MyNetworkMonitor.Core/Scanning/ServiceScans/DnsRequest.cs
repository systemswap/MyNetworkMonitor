// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Builds the DNS query used by both DNS probes; the query is the same,
    /// only the transport differs (RFC 1035, section 4).
    /// </summary>
    internal static class DnsRequest
    {
        /// <summary>Combines header and question into a complete query.</summary>
        /// <param name="domain">The name to ask for, dot-separated.</param>
        /// <returns>The query message without the TCP length prefix.</returns>
        internal static byte[] Build(string domain)
        {
            byte[] header = new byte[]
            {
                0xAA, 0xAA,  // Transaction ID
                0x01, 0x00,  // Standard query, recursion desired
                0x00, 0x01,  // One question
                0x00, 0x00,  // No answer records
                0x00, 0x00,  // No authority records
                0x00, 0x00   // No additional records
            };

            byte[] question = BuildQuestion(domain);
            byte[] query = new byte[header.Length + question.Length];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(question, 0, query, header.Length, question.Length);
            return query;
        }

        /// <summary>
        /// Determines whether an answer belongs to a query.
        /// <para>
        /// Two conditions, both from the DNS header (RFC 1035, section 4.1.1):
        /// the same transaction ID in bytes 0 and 1, and the QR bit (most
        /// significant bit of byte 2) set. Only a real answer to this query
        /// counts, not every datagram that arrives at the socket.
        /// </para>
        /// <para>
        /// Whether the name resolves does not matter: the query asks for a name
        /// that does not exist. An NXDOMAIN answer also comes from a name server
        /// and is therefore a finding.
        /// </para>
        /// </summary>
        /// <param name="query">The query that was sent.</param>
        /// <param name="answer">The received message.</param>
        /// <returns><c>true</c> if <paramref name="answer"/> is a response to <paramref name="query"/>.</returns>
        internal static bool IsAnswerTo(byte[] query, byte[] answer)
        {
            if (query.Length < 3 || answer.Length < 3) return false;

            bool gleicheKennung = answer[0] == query[0] && answer[1] == query[1];
            bool istAntwort = (answer[2] & 0x80) != 0;

            return gleicheKennung && istAntwort;
        }

        /// <summary>
        /// The question section: each label preceded by its length, then the
        /// terminating zero, then type A and class IN.
        /// </summary>
        private static byte[] BuildQuestion(string domain)
        {
            var parts = domain.Split('.');
            byte[] question = new byte[domain.Length + 2 + 4];
            int position = 0;

            foreach (var part in parts)
            {
                question[position++] = (byte)part.Length;
                Encoding.ASCII.GetBytes(part, 0, part.Length, question, position);
                position += part.Length;
            }

            question[position++] = 0x00; // Root label (terminator)
            question[position++] = 0x00; // Type: A (IPv4 address)
            question[position++] = 0x01;
            question[position++] = 0x00; // Class: IN (Internet)
            question[position++] = 0x01;

            return question;
        }
    }
}
