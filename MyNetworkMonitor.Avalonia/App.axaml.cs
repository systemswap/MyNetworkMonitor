// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Linq;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using MyNetworkMonitor.Avalonia.Platform.Linux;
#if WINDOWS
using MyNetworkMonitor.Platform.Windows;
#endif
using MyNetworkMonitor.Avalonia.Views;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia;

/// <summary>The Avalonia application: registers the platform providers and chooses the start window.</summary>
public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Platform implementations for the neutral scan engine in Core.
        // The list lives in PlatformRegistration because the satellite service
        // needs the same list and runs without Avalonia.
        PlatformRegistration.RegisterAll();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // The license notice: see NoticeSuspended. --notice forces it,
            // --no-notice suppresses it for an unattended run; an instance with
            // its own state folder (test instance) does not show it either.
            bool forced = desktop.Args?.Any(a =>
                string.Equals(a, "--notice", StringComparison.OrdinalIgnoreCase)) == true;

            SkipEnterpriseNotice = !forced &&
                (NoticeSuspended || AppPaths.HasOwnState || desktop.Args?.Any(a =>
                    string.Equals(a, "--no-notice", StringComparison.OrdinalIgnoreCase)) == true);

            desktop.MainWindow = CreateStartWindow(desktop);
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>
    /// Whether the license notice in a company network is suspended. With
    /// <c>false</c> the notice is <b>active</b>: when a company network is
    /// detected, it is shown as the start window before the main window.
    /// <para>
    /// <b>Setting this to <c>true</c> is enough to switch it off.</b> Neither
    /// the notice itself (<c>EnterpriseMessageView</c>) nor the company network
    /// detection needs to change for that.
    /// </para>
    /// <para>
    /// While active, the notice is the start window, and as long as it is open
    /// the main window does not exist yet: every start without a mouse click
    /// stops there. Unattended runs therefore use <c>--no-notice</c>.
    /// </para>
    /// </summary>
    private const bool NoticeSuspended = false;

    /// <summary>Whether the license notice is skipped, see <see cref="NoticeSuspended"/>.</summary>
    private static bool SkipEnterpriseNotice { get; set; }

    private static global::Avalonia.Controls.Window CreateMainWindow() => new ShellView();

    /// <summary>
    /// In a company network the license notice comes before the main window:
    /// only a click on OK releases it, any other way (X, Alt+F4) exits the
    /// application.
    ///
    /// A modal dialog in Avalonia needs an owner window, and the main window
    /// must not exist before the notice is confirmed. The notice is therefore
    /// the start window itself and creates the main window only after it has
    /// been confirmed.
    /// </summary>
    private static global::Avalonia.Controls.Window CreateStartWindow(IClassicDesktopStyleApplicationLifetime desktop)
    {
        if (SkipEnterpriseNotice) return CreateMainWindow();

        bool isCompanyNetwork;

        try
        {
            isCompanyNetwork = PlatformServices.EnterpriseOrNull?.IsCompanyNetwork() == true;
        }
        catch (Exception)
        {
            // A failed detection must never prevent the start.
            isCompanyNetwork = false;
        }

        if (!isCompanyNetwork) return CreateMainWindow();

        var notice = new EnterpriseMessageView();

        notice.Accepted += () =>
        {
            // The try is required. If creating the main window fails, it is
            // never shown; the notice closes anyway, no window is left open,
            // and the default shutdown mode (OnLastWindowClose) exits the
            // application. It would look as if clicking OK quits the program,
            // without any message.
            try
            {
                var mainWindow = CreateMainWindow();

                // Reassigns MainWindow so that later dialogs find the right
                // owner window (AvaloniaDialogService reads it).
                desktop.MainWindow = mainWindow;
                mainWindow.Show();
            }
            catch (Exception ex)
            {
                ShowStartupFailure(desktop, ex);
            }
        };

        return notice;
    }

    /// <summary>
    /// Shows why the start failed, in a window of its own, because at this point
    /// no other window exists.
    /// <para>
    /// Without this window the application disappears silently, and the error
    /// is visible only on the console, which is not open when started by
    /// double-click. The text is selectable so that it can be passed on.
    /// </para>
    /// </summary>
    private static void ShowStartupFailure(IClassicDesktopStyleApplicationLifetime desktop, Exception error)
    {
        var window = new global::Avalonia.Controls.Window
        {
            Title = "MyNetworkMonitor could not start",
            Width = 720,
            Height = 420,
            WindowStartupLocation = global::Avalonia.Controls.WindowStartupLocation.CenterScreen,
            Content = new global::Avalonia.Controls.ScrollViewer
            {
                Padding = new global::Avalonia.Thickness(16),
                Content = new global::Avalonia.Controls.SelectableTextBlock
                {
                    FontFamily = new global::Avalonia.Media.FontFamily("Consolas, Menlo, monospace"),
                    FontSize = 12,
                    TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
                    Text = "The main window could not be opened.\n\n" + error
                }
            }
        };

        desktop.MainWindow = window;
        window.Show();
    }
}
