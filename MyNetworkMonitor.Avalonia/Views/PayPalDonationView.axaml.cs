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
    /// Donation window: chooses the currency from the system language, accepts
    /// only digits in the amount field and opens the donation URL in the
    /// default browser.
    /// </summary>
    public partial class PayPalDonationView : Window
    {
        private string Currency = "USD";

        public PayPalDonationView()
        {
            InitializeComponent();

            // System language: German -> EUR, otherwise USD.
            string systemLang = CultureInfo.CurrentCulture.TwoLetterISOLanguageName;
            Currency = systemLang == "de" ? "EUR" : "USD";
            CurrencyTextBlock.Text = Currency;

            // Allows only digits in the amount field; the tunneling handler rejects input before the TextBox sees it.
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

                // Builds the query by hand (platform-neutral, without System.Web).
                var query = new StringBuilder();
                void Add(string key, string value)
                {
                    if (query.Length > 0) query.Append('&');
                    query.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
                }

                // One-time donation.
                Add("cmd", "_donations");
                Add("business", paypalEmail);
                Add("amount", amount.ToString("0.00", CultureInfo.InvariantCulture));
                Add("currency_code", Currency);
                Add("item_name", itemName);
                Add("no_note", "0");
                Add("no_shipping", "1");
                Add("undefined_amount", "1");

                string donationUrl = $"{baseUrl}?{query}";

                // Opens the default browser (Windows: shell association, Linux: xdg-open).
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
