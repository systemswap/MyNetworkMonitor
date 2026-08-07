using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Avalonia.Views;

/// <summary>
/// Die Farbwerte der neuen Oberflaeche an einer Stelle. Farbe traegt hier
/// Bedeutung, nicht Schmuck: Tuerkis fuer IPv4, Indigo fuer IPv6, und davon
/// getrennt die Ampelfarben der Portzustaende. Verstreut im XAML waere die
/// Regel nach der dritten Aenderung nicht mehr durchgehalten.
/// </summary>
internal static class ShellPalette
{
    internal static readonly SolidColorBrush Ink = new(Color.Parse("#142326"));
    internal static readonly SolidColorBrush Dimmer = new(Color.Parse("#A8B7BA"));
    internal static readonly SolidColorBrush Teal = new(Color.Parse("#0B7C8B"));
    internal static readonly SolidColorBrush V6 = new(Color.Parse("#5A4FCF"));

    internal static readonly SolidColorBrush Online = new(Color.Parse("#22A06B"));
    internal static readonly SolidColorBrush Offline = new(Color.Parse("#C0CCCE"));

    internal static readonly SolidColorBrush RunBg = new(Color.Parse("#DFF0E6"));
    internal static readonly SolidColorBrush RunFg = new(Color.Parse("#2C7F51"));
    internal static readonly SolidColorBrush OpenBg = new(Color.Parse("#E4F0EA"));
    internal static readonly SolidColorBrush OpenFg = new(Color.Parse("#3D7A5C"));
    internal static readonly SolidColorBrush WarnBg = new(Color.Parse("#FAEBD3"));
    internal static readonly SolidColorBrush WarnFg = new(Color.Parse("#A66A12"));
    internal static readonly SolidColorBrush MuteBg = new(Color.Parse("#EDF1F2"));
    internal static readonly SolidColorBrush MuteFg = new(Color.Parse("#96A7AB"));
    internal static readonly SolidColorBrush Nothing = new(Colors.Transparent);

    // Die Befundfarben der bisherigen Anwendung, auf die hellere Tabelle
    // dieser Oberflaeche gebracht. Die Zuordnung bleibt: je roeter, desto
    // schwerer der Befund.
    internal static readonly SolidColorBrush DupAddrBg = new(Color.Parse("#F6D9D6"));
    internal static readonly SolidColorBrush DupAddrFg = new(Color.Parse("#8E2B23"));
    internal static readonly SolidColorBrush DupNameBg = new(Color.Parse("#FAE3CC"));
    internal static readonly SolidColorBrush DupNameFg = new(Color.Parse("#8A5310"));
    internal static readonly SolidColorBrush DupSoftBg = new(Color.Parse("#FCF2D9"));
    internal static readonly SolidColorBrush DupSoftFg = new(Color.Parse("#7C6416"));
}

/// <summary>Gruener Punkt, wenn erreichbar - sonst grau.</summary>
public sealed class OnlineBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? ShellPalette.Online : ShellPalette.Offline;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>IPv4-Adresse in Textfarbe, ein Fehlen blass.</summary>
public sealed class Ipv4BrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? ShellPalette.Ink : ShellPalette.Dimmer;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>IPv6 durchgehend in Indigo, ein Fehlen blass.</summary>
public sealed class Ipv6BrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? ShellPalette.V6 : ShellPalette.Dimmer;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Fehlende Angaben kursiv - damit "keine" nicht wie eine Adresse aussieht.
/// </summary>
public sealed class MissingStyleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? FontStyle.Normal : FontStyle.Italic;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Farbe nach Adressfamilie - die durchgaengige Regel des Entwurfs.</summary>
public sealed class FamilyBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is IpFamily.IPv6 ? ShellPalette.V6 : ShellPalette.Teal;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Die Herkunft des Interface-Identifiers nur zeigen, wenn sie etwas aussagt.
/// "NotApplicable" bei IPv4 und "Unknown" sind keine Information.
/// </summary>
public sealed class IidVisibleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is InterfaceIdKind kind &&
        kind is not (InterfaceIdKind.NotApplicable or InterfaceIdKind.Unknown);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Kurzform des Portzustands. Die sieben Zustaende bleiben unterscheidbar,
/// weil sie fachlich Verschiedenes bedeuten - nur die Benennung wird kuerzer,
/// damit sie in eine schmale Spalte passt.
/// </summary>
public sealed class PortStatusTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value as PortStatus? switch
        {
            PortStatus.IsRunning => "running",
            PortStatus.Error => "other",
            PortStatus.Open => "open",
            PortStatus.Closed => "closed",
            PortStatus.Filtered => "filtered",
            PortStatus.NoResponse => "-",
            PortStatus.UnknownResponse => "unclear",
            _ => string.Empty
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class PortStatusBackgroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value as PortStatus? switch
        {
            PortStatus.IsRunning => ShellPalette.RunBg,
            PortStatus.Open => ShellPalette.OpenBg,
            PortStatus.Error => ShellPalette.WarnBg,
            PortStatus.Closed or PortStatus.Filtered
                or PortStatus.UnknownResponse or PortStatus.NoResponse => ShellPalette.MuteBg,
            _ => ShellPalette.Nothing
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class PortStatusForegroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value as PortStatus? switch
        {
            PortStatus.IsRunning => ShellPalette.RunFg,
            PortStatus.Open => ShellPalette.OpenFg,
            PortStatus.Error => ShellPalette.WarnFg,
            _ => ShellPalette.MuteFg
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Das Kuerzel in der Befundspalte. Kurz genug fuer eine schmale Spalte,
/// eindeutig genug, um ohne Legende zu verstehen, worum es geht - der
/// vollstaendige Text steht im Kurzhinweis daneben.
/// </summary>
public sealed class ConflictLabelConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not DeviceConflict conflict || conflict == DeviceConflict.None) return string.Empty;

        // Nur der schwerste Befund kommt in die Spalte. Mehrere Kuerzel
        // nebeneinander waeren in 44 Pixeln nicht mehr zu lesen.
        if (conflict.HasFlag(DeviceConflict.Address)) return "DUP IP";
        if (conflict.HasFlag(DeviceConflict.DnsMultipleAddresses)) return "DNS x";
        if (conflict.HasFlag(DeviceConflict.HostName)) return "DUP NAME";
        if (conflict.HasFlag(DeviceConflict.DuplicateAlias)) return "DUP ALIAS";
        if (conflict.HasFlag(DeviceConflict.DnsMismatch)) return "DNS ?";
        if (conflict.HasFlag(DeviceConflict.DnsMultipleNames)) return "ALIAS";
        if (conflict.HasFlag(DeviceConflict.MultipleIpv4)) return "2x IPv4";

        return "DUP";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Hintergrund des Befundkaestchens - je schwerer, desto roeter.</summary>
public sealed class ConflictBackgroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not DeviceConflict conflict || conflict == DeviceConflict.None) return ShellPalette.Nothing;

        if (conflict.HasFlag(DeviceConflict.Address)) return ShellPalette.DupAddrBg;

        if (conflict.HasFlag(DeviceConflict.DnsMultipleAddresses) ||
            conflict.HasFlag(DeviceConflict.HostName) ||
            conflict.HasFlag(DeviceConflict.DuplicateAlias))
        {
            return ShellPalette.DupNameBg;
        }

        return ShellPalette.DupSoftBg;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Schriftfarbe des Befundkaestchens, passend zum Hintergrund.</summary>
public sealed class ConflictForegroundConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not DeviceConflict conflict || conflict == DeviceConflict.None) return ShellPalette.Nothing;

        if (conflict.HasFlag(DeviceConflict.Address)) return ShellPalette.DupAddrFg;

        if (conflict.HasFlag(DeviceConflict.DnsMultipleAddresses) ||
            conflict.HasFlag(DeviceConflict.HostName) ||
            conflict.HasFlag(DeviceConflict.DuplicateAlias))
        {
            return ShellPalette.DupNameFg;
        }

        return ShellPalette.DupSoftFg;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Faerbt die Zahl der Namensserver. Ueber der plausiblen Grenze wird sie
/// rot - das ist der Befund, um dessentwillen die Spalte ueberhaupt da ist.
/// </summary>
public sealed class DnsCountBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is int count && count > AdapterInfo.MaxPlausibleDnsServers
            ? ShellPalette.DupAddrFg
            : ShellPalette.Ink;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
