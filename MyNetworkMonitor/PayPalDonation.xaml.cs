using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows;
using System.Windows.Input;
using Microsoft.Web.WebView2.Core;

namespace MyNetworkMonitor
{
    public partial class PayPalDonation : Window
    {
        private const string PayPalClientId = "thomas.mueller@tuta.io"; // Nur Client ID, kein Secret nötig!
        private const string Currency = "USD"; // Währung

        public PayPalDonation()
        {
            InitializeComponent();
        }

    

        private void DonateWithPayPal_Click(object sender, RoutedEventArgs e)
        {
            // PayPal-Empfänger-Adresse (fix)
            string paypalEmail = "thomas.mueller@tuta.io";

            // Betrag (anpassbar)
            decimal amount = Convert.ToDecimal(AmountTextBox.Text);

            // Währung (z.B. EUR, USD)
            string currency = "USD";

            // Zahlungszweck (optional)
            string itemName = "thanks for support of MyNetworkMonitor";


            try
            {
                // Basis-URL für PayPal-Spenden
                string baseUrl = "https://www.paypal.com/cgi-bin/webscr";


                // Query-Parameter für den Spendenlink
                var queryParameters = HttpUtility.ParseQueryString(string.Empty);
                queryParameters["cmd"] = "_donations";
                queryParameters["business"] = paypalEmail;
                queryParameters["amount"] = amount.ToString("0.00", CultureInfo.InvariantCulture); // Vorgeschlagener Betrag
                queryParameters["currency_code"] = currency;
                queryParameters["item_name"] = itemName; // Notiz, die auf der PayPal-Seite angezeigt wird
                queryParameters["no_note"] = "0"; // Notizfeld aktivieren
                queryParameters["no_shipping"] = "1"; // Kein Versand erforderlich
                queryParameters["undefined_amount"] = "1"; // Benutzer kann Betrag auf PayPal ändern


                // Endgültige URL generieren
                string donationUrl = $"{baseUrl}?{queryParameters}";

                // Öffne den Standardbrowser mit dem PayPal-Link
                //Process.Start(new ProcessStartInfo
                //{
                //    FileName = donationUrl,
                //    UseShellExecute = true
                //});

                // WebView2 sichtbar machen und gesamte UI ausblenden
                PayPalWebView.Visibility = Visibility.Collapsed;
                PayPalWebView.Visibility = Visibility.Visible;
                PayPalWebView.Source = new Uri(donationUrl);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fehler beim Öffnen der PayPal-Spendenseite: " + ex.Message);
            }
        }

        private void AmountTextBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            // Erlaubt nur Zahlen (0-9)
            if (!Regex.IsMatch(e.Text, "^[0-9]+$"))
            {
                e.Handled = true; // Blockiert ungültige Zeichen
            }
        }

        private void AmountTextBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            // Blockiert das Einfügen von Text (Strg+V, Shift+Insert) und das Leerzeichen
            if (e.Key == Key.Space ||
                (e.Key == Key.V && Keyboard.Modifiers == ModifierKeys.Control) ||
                (e.Key == Key.Insert && Keyboard.Modifiers == ModifierKeys.Shift))
            {
                e.Handled = true;
            }
        }
    }
}
