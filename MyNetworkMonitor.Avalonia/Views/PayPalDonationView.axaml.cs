using System;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Avalonia-Portierung von PayPalDonation (WPF). Verhalten unveraendert:
    /// Waehrung nach Systemsprache, nur Ziffern im Betrag, Spenden-URL im
    /// Standardbrowser oeffnen.
    /// </summary>
    public partial class PayPalDonationView : Window
    {
        private string Currency = "USD";

        public PayPalDonationView()
        {
            InitializeComponent();

            // Systemsprache: Deutsch -> EUR, sonst USD
            string systemLang = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            Currency = systemLang == "de" ? "EUR" : "USD";
            CurrencyTextBlock.Text = Currency;

            // Nur Ziffern im Betragsfeld zulassen (Gegenstueck zu PreviewTextInput).
            AmountTextBox.AddHandler(TextInputEvent, OnAmountTextInput, RoutingStrategies.Tunnel);
        }

        private void OnAmountTextInput(object? sender, TextInputEventArgs e)
        {
            if (!string.IsNullOrEmpty(e.Text) && !Regex.IsMatch(e.Text, "^[0-9]+$"))
                e.Handled = true;
        }

        private void DonateWithPayPal_Click(object? sender, RoutedEventArgs e)
        {
            const string paypalEmail = "systemswap@tuta.io";
            const string itemName = "support of MyNetworkMonitor";

            decimal amount;
            if (!decimal.TryParse(AmountTextBox.Text, NumberStyles.Any, CultureInfo.CurrentCulture, out amount))
                return;

            try
            {
                const string baseUrl = "https://www.paypal.com/cgi-bin/webscr";

                // Query manuell aufbauen (plattformneutral, ohne System.Web).
                var query = new StringBuilder();
                void Add(string key, string value)
                {
                    if (query.Length > 0) query.Append('&');
                    query.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
                }

                // Einmalige Spende (Abo-Zweig war im Original deaktiviert).
                Add("cmd", "_donations");
                Add("business", paypalEmail);
                Add("amount", amount.ToString("0.00", CultureInfo.InvariantCulture));
                Add("currency_code", Currency);
                Add("item_name", itemName);
                Add("no_note", "0");
                Add("no_shipping", "1");
                Add("undefined_amount", "1");

                string donationUrl = $"{baseUrl}?{query}";

                // Standardbrowser oeffnen (Windows: Browser, Linux: xdg-open).
                Process.Start(new ProcessStartInfo
                {
                    FileName = donationUrl,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fehler beim Öffnen der PayPal-Spendenseite: " + ex.Message);
            }
        }
    }
}
