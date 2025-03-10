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
using System.Windows.Threading;

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
                Title = "Notice: Enterprise Network detected.",
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
            TextBlock contactText = new TextBlock { Text = "If you need a licensed version, contact us: ", TextAlignment = TextAlignment.Center };

            // Erstellen des Run-Objekts für die E-Mail-Adresse mit einer benutzerdefinierten Schriftgröße
            Run emailRun = new Run("syswap@tuta.io")
            {
                FontSize = 14 // Schriftgröße für die E-Mail-Adresse festlegen
            };

            // Erstellen des Hyperlinks mit dem Run
            Hyperlink emailLink = new Hyperlink(emailRun)
            {
                NavigateUri = new Uri("mailto:syswap@tuta.io"),
                Foreground = new SolidColorBrush(Color.FromRgb(0, 112, 186)) // Blau für Seriosität
            };

            // Ereignis, um den E-Mail-Client zu öffnen, wenn der Hyperlink angeklickt wird
            emailLink.RequestNavigate += (s, e) => Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });

            // Hinzufügen des Hyperlinks zu den Inlines des TextBlocks
            contactText.Inlines.Add(emailLink);

            int countdown = 30;

            // OK-Button
            Button closeButton = new Button
            {
                Content = $"You can click OK in: {countdown} seconds",
                Width = 250,
                Height = 50,
                Background = new SolidColorBrush(Color.FromRgb(0, 112, 186)), // Blau für Konsistenz
                //Foreground = Brushes.White,
                Foreground = new SolidColorBrush(Color.FromRgb(169, 169, 169)),
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 20, 0, 0),
                Cursor = System.Windows.Input.Cursors.Hand,
                IsEnabled = false // Button wird zunächst deaktiviert
            };

            // Timer erstellen und starten
            DispatcherTimer timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromSeconds(1);


            // Countdown-Tick-Ereignis
            timer.Tick += (s, e) =>
            {
                countdown--;
                closeButton.Content = $"You can click OK in: {countdown} seconds";

                // Wenn Countdown 0 erreicht, Button aktivieren
                if (countdown <= 0)
                {
                    closeButton.Foreground = Brushes.White; // Zurück zu Weiß
                    closeButton.Content = "OK";
                    closeButton.IsEnabled = true; // Button aktivieren
                    timer.Stop(); // Timer stoppen
                }
            };
            timer.Start();

            closeButton.Click += (s, e) => window.Close();


            // Schließen des Fensters abfangen
            window.Closing += (sender, e) =>
            {
                // Wenn das Fenster durch das "X" geschlossen wird
                if (!closeButton.IsEnabled)
                {
                    // Die gesamte Anwendung wird hier geschlossen
                    Application.Current.Shutdown();
                }
            };

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
