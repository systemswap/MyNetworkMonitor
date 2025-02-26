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
        private string Currency = "USD"; // Währung

        public PayPalDonation()
        {
            InitializeComponent();

            // Systemsprache abrufen
            string systemLang = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;

            // Falls Deutsch → EUR, sonst USD
            if (systemLang == "de")
                Currency = "EUR";
            else
                Currency = "USD";

            // Währung im UI aktualisieren
            CurrencyTextBlock.Text = Currency;
        }

    

        private void DonateWithPayPal_Click(object sender, RoutedEventArgs e)
        {
            // PayPal-Empfänger-Adresse (fix)
            string paypalEmail = "thomas.mueller@tuta.io";

            // Betrag (anpassbar)
            decimal amount = Convert.ToDecimal(AmountTextBox.Text);

            // Währung (z.B. EUR, USD)
            string currency = Currency;

            // Zahlungszweck (optional)
            string itemName = "support of MyNetworkMonitor";


            try
            {
              
                    string baseUrl = "https://www.paypal.com/cgi-bin/webscr";
                    var queryParameters = HttpUtility.ParseQueryString(string.Empty);

                    if (SubscriptionCheckBox.IsChecked == true) // Wenn Abo ausgewählt
                    {
                        queryParameters["cmd"] = "_xclick-subscriptions";
                        queryParameters["business"] = paypalEmail;
                        queryParameters["a3"] = amount.ToString("0.00", CultureInfo.InvariantCulture);
                        queryParameters["p3"] = "1"; // Alle 1 Jahr
                        queryParameters["t3"] = "Y"; // Zeitraum = Jahr
                        queryParameters["src"] = "1"; // Automatische Verlängerung aktivieren
                        queryParameters["sra"] = "1"; // Falls gekündigt, keine neue Buchung
                        queryParameters["currency_code"] = currency;
                        queryParameters["item_name"] = itemName;
                    }
                    else // Einmalige Spende
                    {
                        queryParameters["cmd"] = "_donations";
                        queryParameters["business"] = paypalEmail;
                        queryParameters["amount"] = amount.ToString("0.00", CultureInfo.InvariantCulture);
                        queryParameters["currency_code"] = currency;
                        queryParameters["item_name"] = itemName;
                        queryParameters["no_note"] = "0";
                        queryParameters["no_shipping"] = "1";
                        queryParameters["undefined_amount"] = "1";
                    }

                    string donationUrl = $"{baseUrl}?{queryParameters}";

                    // WebView2 sichtbar machen und gesamte UI ausblenden
                    PayPalWebView.Visibility = Visibility.Collapsed;
                PayPalWebView.Visibility = Visibility.Visible;
                PayPalWebView.Source = new Uri(donationUrl);

                System.Threading.Tasks.Task.Delay(1500).Wait();

                this.Height = 780;
                this.Width = 850;
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

        private void SubscriptionCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            AmountTextBox.Text = "99"; // Standardbetrag für jährliches Abo
        }

        private void SubscriptionCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            AmountTextBox.Text = "25"; // Standardbetrag für einmalige Spende
        }
    }
}
