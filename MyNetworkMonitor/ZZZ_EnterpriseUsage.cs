using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows;
using Microsoft.Win32;
using System.Diagnostics;
using System.Windows.Media.Effects;

namespace MyNetworkMonitor
{
    static class ZZZ_EnterpriseUsage
    {

        public static bool IsCompanyNetwork()
        {
            return IsDomainJoined() || IsAzureADUser() || IsAzureADJoined() || IsDomainUser() || IsCompanyIP();
        }

        static bool IsDomainJoined()
        {
            try
            {
                Domain domain = Domain.GetComputerDomain();
                return true;
            }
            catch
            {
                return false;
            }
        }

        static bool IsDomainUser()
        {
            string userDomain = Environment.UserDomainName;
            string computerName = Environment.MachineName;
            return !string.IsNullOrEmpty(userDomain) && userDomain != computerName;
        }

        static bool IsAzureADUser()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity.User.Value.StartsWith("S-1-12-1-"); // Azure AD SID beginnt mit S-1-12-1
        }

        static bool IsAzureADJoined()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD"))
                {
                    return key != null;
                }
            }
            catch
            {
                return false;
            }
        }

        static bool IsCompanyIP()
        {
            string[] knownCompanyNetworks = { "10.", "172." };

            foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var unicast in netInterface.GetIPProperties().UnicastAddresses)
                {
                    string ip = unicast.Address.ToString();
                    foreach (var companyNetwork in knownCompanyNetworks)
                    {
                        if (ip.StartsWith(companyNetwork))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }




        public static void ShowEnterpriseMessage()
        {
            // Fenster erstellen
            Window window = new Window
            {
                Title = "Notice: Private Use Only",
                Width = 500,
                Height = 350,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterScreen,
                Background = new SolidColorBrush(Color.FromRgb(245, 247, 250)) // Leichter Grauton für modernen Look
            };

            // Hauptcontainer
            Border border = new Border
            {
                Background = Brushes.White,
                Padding = new Thickness(20),
                CornerRadius = new CornerRadius(10),
                Effect = new DropShadowEffect { Color = Colors.Black, Opacity = 0.2, BlurRadius = 10, ShadowDepth = 3 }
            };

            StackPanel panel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };

            // Überschrift
            TextBlock headline = new TextBlock
            {
                Text = "Make a Difference Today ❤️",
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0, 112, 186)), // Seriöses Blau
                TextAlignment = TextAlignment.Center,
                Margin = new Thickness(0, 5, 0, 10)
            };

            // Hauptnachricht
            TextBlock message = new TextBlock
            {
                Text = "This software is free for private use only.\nFor companies and commercial usage, a license is required.",
                FontSize = 14,
                Foreground = Brushes.Black,
                TextAlignment = TextAlignment.Center,
                Margin = new Thickness(0, 5, 0, 15)
            };

            // Entwickler-Unterstützung
            TextBlock devSupport = new TextBlock
            {
                Text = "This project has taken over 450 hours to develop.\nEven Open-Source developers need coffee ☕.",
                FontSize = 13,
                Foreground = Brushes.Gray,
                TextAlignment = TextAlignment.Center,
                Margin = new Thickness(0, 5, 0, 15)
            };

            // Kontakt-Link
            TextBlock contactText = new TextBlock { Text = "If you need a license, contact us: ", TextAlignment = TextAlignment.Center };
            Hyperlink emailLink = new Hyperlink(new Run("syswap@tuta.io"))
            {
                NavigateUri = new Uri("mailto:syswap@tuta.io"),
                Foreground = new SolidColorBrush(Color.FromRgb(0, 112, 186)) // Blau für Seriosität
            };
            emailLink.RequestNavigate += (s, e) => Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });

            contactText.Inlines.Add(emailLink);

            // OK-Button
            Button closeButton = new Button
            {
                Content = "OK",
                Width = 150,
                Height = 40,
                Background = new SolidColorBrush(Color.FromRgb(0, 112, 186)), // Blau für Konsistenz
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 20, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand
            };
            closeButton.Click += (s, e) => window.Close();

            // Elemente hinzufügen
            panel.Children.Add(headline);
            panel.Children.Add(message);
            panel.Children.Add(devSupport);
            panel.Children.Add(contactText);
            panel.Children.Add(closeButton);

            border.Child = panel;
            window.Content = border;
            window.ShowDialog();
        }




    }
}
