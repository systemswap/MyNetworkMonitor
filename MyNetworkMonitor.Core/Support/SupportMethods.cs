// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
    /// <summary>Helper methods for MAC vendor lookup, IP address validation and interface queries.</summary>
    public class SupportMethods
    {
        /// <summary>Checks whether the process runs with administrator rights (Windows only).</summary>
        /// <returns><c>true</c> if the current Windows identity is in the Administrators role.</returns>
        public bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }


        /// <summary>Column names of the MAC vendor list; the first column is the MAC prefix.</summary>
        public string[] header;
        private string[][] fields;

        private void LoadMacVendors()
        {
            // Search order, see AppDataPaths: first the self-updated list in the
            // user folder, then the bundled list next to the application, last
            // the working directory. The last step matters because ".\MacVendors"
            // is missing when the application is started from another
            // directory - the scan (the ARP request calls GetVendorFromMac)
            // would otherwise terminate the application.
            string csvPath = string.Empty;

            foreach (string candidate in Core.Services.AppDataPaths.MacVendorCsvCandidates)
            {
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
        /// Looks up the vendor of a MAC address.
        /// <para>
        /// <b>Never returns an empty array.</b> Both callers access the first
        /// element without checking (<c>vendor[0]</c> or <c>.First()</c>). If
        /// the vendor list is missing (no <c>MacVendors/mac_vendors.csv</c>), an
        /// empty array would make that access fail and abort the <em>entire</em>
        /// ARP run, reported as the misleading "IPInfo: Error Parsing 'arp -a'
        /// results". Instead of checking at each call site, the source always
        /// returns something usable - which also protects future callers.
        /// </para>
        /// </summary>
        /// <param name="macAdress">The MAC address, with ':' or '-' as separator.</param>
        /// <returns>The vendor columns of the matching entry (without the prefix column); "Unknown" for every column if there is no match.</returns>
        public string[] GetVendorFromMac(string macAdress)
        {
            if (fields == null)
            {
                LoadMacVendors();
            }

            // Without a list there is nothing to look up. "Unknown" is the
            // correct answer here - not no answer at all.
            if (fields.Length == 0 || header.Length == 0)
            {
                return UnknownVendor(1);
            }

            string needle = macAdress.Replace("-", ":").ToLower();

            // Reading f[0] unchecked throws on an empty line in the CSV. An
            // empty prefix, in turn, matches *every* MAC and would make the
            // first record the vendor of all devices.
            string[]? data = fields.FirstOrDefault(f =>
                f.Length > 0 && f[0].Length > 0 && needle.StartsWith(f[0].ToLower()));

            int columns = Math.Max(header.Length - 1, 1);

            if (data is null) return UnknownVendor(columns);

            // A line can have fewer columns than the header - not unusual in a
            // 3 MB third-party CSV. Missing columns are filled in instead of
            // aborting the run.
            string[] result = new string[columns];
            for (int i = 0; i < columns; i++)
            {
                result[i] = i + 1 < data.Length ? data[i + 1] : "Unknown";
            }

            return result;
        }

        /// <summary>A result consisting only of "Unknown", with at least one column.</summary>
        private static string[] UnknownVendor(int count)
        {
            string[] result = new string[Math.Max(count, 1)];
            Array.Fill(result, "Unknown");
            return result;
        }

        /// <summary>Returns the vendor column names without the prefix column.</summary>
        /// <returns>The column names of the MAC vendor list after the first one.</returns>
        public string[] GetHeader()
        {
            return header!.Skip(1).ToArray();
        }

        /// <summary>Checks whether a text is a dotted-decimal IPv4 address.</summary>
        /// <param name="ip">The text to check.</param>
        /// <returns><c>true</c> for four octets from 0 to 255.</returns>
        public bool Is_Valid_IP(string ip)
        {
            string pattern = @"^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$";

            Regex regex = new Regex(pattern);

            return regex.IsMatch(ip);
        }

        /// <summary>Result of <see cref="ValidAndCleanIP"/>.</summary>
        public class ValidAndCleanedIP
        {
            /// <summary>Whether the input is a valid IPv4 address.</summary>
            public bool IsValid { get; set; }
            /// <summary>The address without leading zeros; empty if invalid.</summary>
            public string IP { get; set; }
        }

        /// <summary>Validates an IPv4 address and removes leading zeros from its octets.</summary>
        /// <param name="ip">The address as text; leading zeros are allowed.</param>
        /// <returns>The validation result and the cleaned address.</returns>
        public ValidAndCleanedIP ValidAndCleanIP(string ip)
        {
            // Leading zeros are accepted on purpose: zero-padded addresses
            // (such as 010.000.000.001) sort correctly as text.
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
                // Version removes leading zeros after the dots.
                validAndCleanedIP.IP = new Version(ip).ToString();
            }
            else
            {
                validAndCleanedIP.IP = string.Empty;
            }

            return validAndCleanedIP;
        }

        /// <summary>Returns the first IPv4 address of an active network interface.</summary>
        /// <param name="interfaceName">The interface name, compared case-insensitively.</param>
        /// <returns>The IPv4 address as text.</returns>
        /// <exception cref="Exception">The interface is not found, not up, or has no IPv4 address.</exception>
        public static string GetIPAddressByInterfaceName(string interfaceName)
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase) && ni.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)  // IPv4 addresses only
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }
            throw new Exception($"No IPv4 address found for interface '{interfaceName}', or the interface is not active.");
        }

        /// <summary>The network interface selected for scanning.</summary>
        public static class SelectedNetworkInterfaceInfos
        {
            /// <summary>Interface name.</summary>
            public static string Name { get; set; }
            /// <summary>IPv4 address of the interface.</summary>
            public static IPAddress IPv4 { get; set; }
            /// <summary><see cref="IPv4"/> as text.</summary>
            public static string IPv4_string { get { return IPv4.ToString(); } }
        }

        /// <summary>Returns the <see cref="DescriptionAttribute"/> text of an enum value.</summary>
        /// <param name="value">The enum value.</param>
        /// <returns>The description, or the value name if there is none.</returns>
        public static string GetEnumDescription(Enum value)
        {
            FieldInfo fi = value.GetType().GetField(value.ToString());
            DescriptionAttribute[] attributes = (DescriptionAttribute[])fi.GetCustomAttributes(typeof(DescriptionAttribute), false);

            return attributes.Length > 0 ? attributes[0].Description : value.ToString();
        }
    }
}
