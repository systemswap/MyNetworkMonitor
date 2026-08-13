using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Baut die DNS-Anfrage, mit der beide DNS-Sonden fragen - dieselbe
    /// Anfrage, nur der Weg dorthin unterscheidet sich. Wortgleich aus
    /// <c>ScanningMethod_Services</c> uebernommen.
    /// </summary>
    internal static class DnsRequest
    {
        /// <summary>Kopf und Frage zu einer vollstaendigen Anfrage zusammensetzen.</summary>
        internal static byte[] Build(string domain)
        {
            byte[] header = new byte[]
            {
                0xAA, 0xAA,  // Transaction ID
                0x01, 0x00,  // Standard Query mit rekursiver Abfrage
                0x00, 0x01,  // Eine Frage
                0x00, 0x00,  // Keine Antworten vorhanden
                0x00, 0x00,  // Keine Autoritaetsantworten
                0x00, 0x00   // Keine zusaetzlichen Antworten
            };

            byte[] question = BuildQuestion(domain);
            byte[] query = new byte[header.Length + question.Length];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(question, 0, query, header.Length, question.Length);
            return query;
        }

        /// <summary>
        /// Gehoert diese Antwort zu dieser Anfrage?
        /// <para>
        /// Zwei Bedingungen, beide aus dem DNS-Kopf: dieselbe
        /// Transaktionskennung in Byte 0 und 1, und das Antwortbit (oberstes
        /// Bit von Byte 2) muss gesetzt sein. Damit zaehlt nur, was wirklich
        /// auf die eigene Frage antwortet - nicht jedes Datagramm, das am
        /// Socket ankommt.
        /// </para>
        /// <para>
        /// Ob der Name aufloest, bleibt weiterhin gleichgueltig: gefragt wird
        /// nach einem Namen, den es nicht gibt. Auch ein "kenne ich nicht" ist
        /// die Antwort eines Namensservers und damit ein Fund.
        /// </para>
        /// </summary>
        internal static bool IsAnswerTo(byte[] query, byte[] answer)
        {
            if (query.Length < 3 || answer.Length < 3) return false;

            bool gleicheKennung = answer[0] == query[0] && answer[1] == query[1];
            bool istAntwort = (answer[2] & 0x80) != 0;

            return gleicheKennung && istAntwort;
        }

        /// <summary>
        /// Der Frageteil: jeder Namensabschnitt mit seiner Laenge davor, dann
        /// die Null, dann Typ A und Klasse IN.
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

            question[position++] = 0x00; // Null-Terminierung
            question[position++] = 0x00; // Type: A (IPv4-Adresse anfragen)
            question[position++] = 0x01;
            question[position++] = 0x00; // Class: IN (Internet)
            question[position++] = 0x01;

            return question;
        }
    }
}
