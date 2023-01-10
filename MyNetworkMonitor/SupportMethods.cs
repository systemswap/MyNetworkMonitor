using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MyNetworkMonitor
{
    internal class SupportMethods
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
            string csvPath = Directory.GetFiles(@".\MacVendors", "mac_vendors.csv").First();
            if (!File.Exists(csvPath))
            {
                header = Array.Empty<string>();
                fields = Array.Empty<string[]>();
                return;
            }

            string[] lines = File.ReadAllLines(csvPath);

            header = lines[0].Split(',');
            fields = lines.Skip(1).Select(l => Regex.Split(l, ",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))")).ToArray();
        }

        public string[] GetVendorFromMac(string macAdress)
        {
            if (fields == null)
            {
                LoadMacVendors();
            }

            string[]? data = fields.FirstOrDefault(f => macAdress.Replace("-",":").ToLower().StartsWith(f[0].ToLower()))?.ToArray();

            if (fields.Length == 0 || header.Length == 0)
            {
                return Array.Empty<string>();
            }
            else if (data is null)
            {
                string[] result = new string[header.Length - 1];
                for (int i = 0; i < result.Length; i++)
                {
                    result[i] = "Unknown";
                }
                return result;
            }
            else
            {
                List<string> result = new List<string>();
                for (int i = 1; i < header.Length; i++)
                {
                    result.Add($"{data[i]}");
                }
                return result.ToArray();
            }
        }

        public string[] GetHeader()
        {
            return header!.Skip(1).ToArray();
        }

       

        public bool Is_Valid_IP(string ip)
        {
            // (?!0) check if the numeric part starts with zero
            string pattern = "" +
                "^(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

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
}

