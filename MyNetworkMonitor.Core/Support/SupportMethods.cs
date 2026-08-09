using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MyNetworkMonitor
{
    public class SupportMethods
    {
        public bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }


        public string[] header;
        private string[][] fields;

        private void LoadMacVendors()
        {
            // Zuerst neben der Anwendung suchen, dann im Arbeitsverzeichnis:
            // wird die App aus einem anderen Verzeichnis gestartet, existiert
            // ".\MacVendors" nicht und Directory.GetFiles wirft - der Scan
            // (ARP-Request ruft GetVendorFromMac) wuerde die App beenden.
            string csvPath = string.Empty;

            foreach (string root in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
            {
                string candidate = Path.Combine(root, "MacVendors", "mac_vendors.csv");
                if (File.Exists(candidate))
                {
                    csvPath = candidate;
                    break;
                }
            }

            if (string.IsNullOrEmpty(csvPath))
            {
                header = Array.Empty<string>();
                fields = Array.Empty<string[]>();
                return;
            }

            string[] lines = File.ReadAllLines(csvPath);

            header = lines[0].Split(',');
            fields = lines.Skip(1).Select(l => Regex.Split(l, ",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))")).ToArray();
        }

        /// <summary>
        /// Schlaegt den Hersteller zu einer MAC-Adresse nach.
        /// <para>
        /// <b>Liefert nie ein leeres Feld.</b> Beide Aufrufer greifen ungeprueft
        /// auf das erste Element zu (<c>vendor[0]</c> bzw. <c>.First()</c>) -
        /// frueher kam bei fehlender Herstellerliste
        /// <see cref="Array.Empty{T}()"/> zurueck, und der Zugriff darauf riss
        /// den <em>gesamten</em> ARP-Lauf mit, gemeldet als das irrefuehrende
        /// "IPInfo: Error Parsing 'arp -a' results". Am 2026-08-09 in einer
        /// Umgebung ohne <c>MacVendors/mac_vendors.csv</c> ausgeloest. Statt an
        /// zwei Aufrufstellen zu pruefen, gibt die Quelle jetzt immer etwas
        /// Brauchbares zurueck - das haelt auch kuenftige Aufrufer heil.
        /// </para>
        /// </summary>
        public string[] GetVendorFromMac(string macAdress)
        {
            if (fields == null)
            {
                LoadMacVendors();
            }

            // Ohne Liste gibt es nichts nachzuschlagen. Ein "Unknown" ist hier
            // die richtige Antwort - nicht "gar keine".
            if (fields.Length == 0 || header.Length == 0)
            {
                return UnknownVendor(1);
            }

            string needle = macAdress.Replace("-", ":").ToLower();

            // f[0] ungeprueft zu lesen wirft bei einer leeren Zeile in der CSV.
            // Ein leeres Praefix wiederum passt auf *jede* MAC und wuerde den
            // ersten Datensatz zum Hersteller aller Geraete machen.
            string[]? data = fields.FirstOrDefault(f =>
                f.Length > 0 && f[0].Length > 0 && needle.StartsWith(f[0].ToLower()));

            int columns = Math.Max(header.Length - 1, 1);

            if (data is null) return UnknownVendor(columns);

            // Eine Zeile kann weniger Spalten haben als der Kopf - bei 3 MB
            // fremder CSV keine Seltenheit. Fehlende Spalten werden aufgefuellt,
            // statt den Lauf zu beenden.
            string[] result = new string[columns];
            for (int i = 0; i < columns; i++)
            {
                result[i] = i + 1 < data.Length ? data[i + 1] : "Unknown";
            }

            return result;
        }

        /// <summary>Ein Ergebnis aus lauter "Unknown", mindestens einspaltig.</summary>
        private static string[] UnknownVendor(int count)
        {
            string[] result = new string[Math.Max(count, 1)];
            Array.Fill(result, "Unknown");
            return result;
        }

        public string[] GetHeader()
        {
            return header!.Skip(1).ToArray();
        }



        public bool Is_Valid_IP(string ip)
        {
            // (?!0) check if the numeric part starts with zero
            //string pattern = "" +
            //    "^(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
            //    "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
            //    "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
            //    "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            string pattern = @"^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$";

            Regex regex = new Regex(pattern);

            return regex.IsMatch(ip);
        }

        public class ValidAndCleanedIP
        {
            public bool IsValid { get; set; }
            public string IP { get; set; }
        }

        public ValidAndCleanedIP ValidAndCleanIP(string ip)
        {
            // ^(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?!0) check if the numeric part starts not with zero, optional you can use this pattern (25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1][0-9]|[1-9])
            // there is no check for leading zero becaus there is it possible to order the IP Addresses
            string pattern = "" +
                "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            Regex regex = new Regex(pattern);
            bool test = regex.IsMatch(ip);

            ValidAndCleanedIP validAndCleanedIP = new ValidAndCleanedIP();

            validAndCleanedIP.IsValid = test;
            if (test)
            {
                //version removes leading zeros after the dots
                validAndCleanedIP.IP = new Version(ip).ToString();
            }
            else
            {
                validAndCleanedIP.IP = string.Empty;
            }

            return validAndCleanedIP;
        }

        //public static class LanguageUtils
        //{
        //    /// <summary>
        //    /// Runs an operation and ignores any Exceptions that occur.
        //    /// Returns true or falls depending on whether catch was
        //    /// triggered
        //    /// </summary>
        //    /// <param name="operation">lambda that performs an operation that might throw</param>
        //    /// <returns></returns>
        //    public static bool IgnoreErrors(Action operation)
        //    {
        //        if (operation == null)
        //            return false;
        //        try
        //        {
        //            operation.Invoke();
        //        }
        //        catch
        //        {
        //            return false;
        //        }

        //        return true;
        //    }

        //    /// <summary>
        //    /// Runs an function that returns a value and ignores any Exceptions that occur.
        //    /// Returns true or falls depending on whether catch was
        //    /// triggered
        //    /// </summary>
        //    /// <param name="operation">parameterless lamda that returns a value of T</param>
        //    /// <param name="defaultValue">Default value returned if operation fails</param>
        //    public static T IgnoreErrors<T>(Func<T> operation, T defaultValue = default(T))
        //    {
        //        if (operation == null)
        //            return defaultValue;

        //        T result;
        //        try
        //        {
        //            result = operation.Invoke();
        //        }
        //        catch
        //        {
        //            result = defaultValue;
        //        }

        //        return result;
        //    }
        //}

        ////helps to sort IPs
        //public class IPComparer : IComparer<string>
        //{
        //    public int Compare(string a, string b)
        //    {
        //        return Enumerable.Zip(a.Split('.'), b.Split('.'), (x, y) => int.Parse(x).CompareTo(int.Parse(y))).FirstOrDefault(i => i != 0);
        //    }
        //}


        public static string GetIPAddressByInterfaceName(string interfaceName)
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase) && ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)  // Nur IPv4-Adressen
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }
            throw new Exception($"Keine IPv4-Adresse für das Interface '{interfaceName}' gefunden oder Interface ist nicht aktiv.");
        }

        public static class SelectedNetworkInterfaceInfos
        {
            public static string Name { get; set; }
            public static IPAddress IPv4 { get; set; }
            public static string IPv4_string { get { return IPv4.ToString(); } }
        }

        public static string GetEnumDescription(Enum value)
        {
            FieldInfo fi = value.GetType().GetField(value.ToString());
            DescriptionAttribute[] attributes = (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);

            return attributes.Length > 0 ? attributes[0].Description : value.ToString();
        }
    }
}
