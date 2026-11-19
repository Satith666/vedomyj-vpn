// VEDOMYJ VPN — запускалка VedomyjVPN.exe: открывает программу встроенным Python без чёрного окна.
// Собирается build.ps1 штатным компилятором Windows (csc из .NET Framework 4), язык C# 5.
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("VEDOMYJ VPN")]
[assembly: AssemblyProduct("VEDOMYJ VPN")]
[assembly: AssemblyVersion("1.0.0.0")]

static class Launcher
{
    [STAThread]
    static int Main(string[] args)
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(dir, "main.py");
        string python = Path.Combine(dir, "python", "pythonw.exe");
        bool ru = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru";
        if (!File.Exists(python) || !File.Exists(script))
        {
            MessageBox.Show(ru
                ? "Не найдены файлы программы. Переустанови VEDOMYJ VPN или распакуй архив заново."
                : "Program files are missing. Reinstall VEDOMYJ VPN or unpack the archive again.",
                "VEDOMYJ VPN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        string line = Quote(script);
        foreach (string a in args)
        {
            line += " " + Quote(a);
        }
        ProcessStartInfo psi = new ProcessStartInfo(python, line);
        psi.WorkingDirectory = dir;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process.Start(psi);
        return 0;
    }

    static string Quote(string s)
    {
        return "\"" + s.Replace("\"", "\\\"") + "\"";
    }
}
