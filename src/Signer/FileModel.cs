using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Input;

namespace Signer
{
    internal class FileModel : INotifyPropertyChanged
    {
        internal List<FileObject> _files { get; set; } = new List<FileObject>();

        private ICommand _removeItem;
        private ICommand _info;

        public ICommand RemoveItem
        {
            get { return _removeItem ?? (_removeItem = new RelayCommand<FileObject>(p => RemoveItemCommand(p))); }
        }

        public ICommand Info
        {
            get { return _info ?? (_info = new RelayCommand<FileObject>(p => InfoCommand(p))); }
        }

        public void InfoCommand(FileObject item)
        {
            if (item == null || item.Signatures == null)
                return;
            foreach (var c in item.Signatures)
            {
                X509Certificate2UI.DisplayCertificate(c.SigningCertificate);
            }
        }

        private void RemoveItemCommand(FileObject item)
        {
            if (item == null)
                return;
            var tmp = new List<FileObject>();
            _files.Remove(item);
            tmp.AddRange(_files);
            Files = tmp;
        }

        public List<FileObject> Files
        {
            get { return _files; }
            set
            {
                _files.Clear();
                _files = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}