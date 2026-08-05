using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Avalonia-Gegenstück zur WPF-ManageIPGroups. Bewusst logikfrei: die gesamte
    /// Logik liegt im geteilten <see cref="ManageIPGroupsViewModel"/> (Core).
    /// </summary>
    public partial class ManageIPGroupsView : Window
    {
        public ManageIPGroupsView()
        {
            InitializeComponent();
        }

        public ManageIPGroupsView(ManageIPGroupsViewModel viewModel) : this()
        {
            DataContext = viewModel;
            viewModel.CloseRequested += Close;
        }

        private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
    }
}
