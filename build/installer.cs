// VEDOMYJ VPN — установщик и удаление. Внутри лежит архив портативной версии (ресурс app.zip).
// Ставит программу в %LOCALAPPDATA%\Programs\VedomyjVPN без прав администратора, создаёт ярлыки
// и пункт в «Приложениях» Windows. Запуск с /uninstall — удаление.
// Собирается build.ps1 штатным компилятором Windows (csc из .NET Framework 4), язык C# 5.
using System;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("VEDOMYJ VPN Setup")]
[assembly: AssemblyProduct("VEDOMYJ VPN")]
[assembly: AssemblyVersion("1.0.0.0")]

static class Setup
{
    const string Version = "%VERSION%";
    const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\VedomyjVPN";
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    static readonly bool Ru = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru";

    static string T(string ru, string en) { return Ru ? ru : en; }

    [STAThread]
    static int Main(string[] args)
    {
        Application.EnableVisualStyles();
        string target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                     "Programs", "VedomyjVPN");
        bool uninstall = Array.IndexOf(args, "/uninstall") >= 0;
        bool quiet = Array.IndexOf(args, "/quiet") >= 0;
        try
        {
            return uninstall ? Uninstall(target, quiet, Array.IndexOf(args, "/fromtemp") >= 0) : Install(target, quiet);
        }
        catch (Exception ex)
        {
            if (!quiet)
            {
                MessageBox.Show(T("Что-то пошло не так: ", "Something went wrong: ") + ex.Message, "VEDOMYJ VPN",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    // ---------- установка ----------

    static int Install(string target, bool quiet)
    {
        bool update = File.Exists(Path.Combine(target, "main.py"));
        if (!quiet)
        {
            string text = update
                ? T("Обновить VEDOMYJ VPN до версии " + Version + "?\n\nНастройки и подписки сохранятся.",
                    "Update VEDOMYJ VPN to version " + Version + "?\n\nSettings and subscriptions are kept.")
                : T("Установить VEDOMYJ VPN " + Version + "?\n\nПапка: " + target +
                    "\nЯрлыки появятся на рабочем столе и в меню «Пуск». Права администратора не нужны.",
                    "Install VEDOMYJ VPN " + Version + "?\n\nFolder: " + target +
                    "\nShortcuts will appear on the desktop and in the Start menu. No admin rights needed.");
            if (MessageBox.Show(text, "VEDOMYJ VPN", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
            {
                return 2;
            }
        }
        Form wait = ShowWait(T("Устанавливаю VEDOMYJ VPN…", "Installing VEDOMYJ VPN…"), quiet);
        try
        {
            CloseRunning(target);
            Directory.CreateDirectory(target);
            if (update)
            {
                // старые файлы программы убираем, чтобы не остались лишние модули; data и bin не трогаем
                foreach (string dir in new string[] { "pult", "ui", "python" })
                {
                    try { Directory.Delete(Path.Combine(target, dir), true); } catch (Exception) { }
                }
            }
            Extract(target);
            string self = Assembly.GetExecutingAssembly().Location;
            File.Copy(self, Path.Combine(target, "Uninstall.exe"), true);
            string exe = Path.Combine(target, "VedomyjVPN.exe");
            Shortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "VEDOMYJ VPN.lnk"), exe, target);
            Shortcut(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "VEDOMYJ VPN.lnk"), exe, target);
            Register(target, exe);
            // автозапуск, если был включён, должен указывать на новую запускалку
            using (RegistryKey run = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                if (run != null && run.GetValue("VedomyjVPN") != null)
                {
                    run.SetValue("VedomyjVPN", "\"" + exe + "\" --autostart");
                }
            }
        }
        finally
        {
            if (wait != null) wait.Close();
        }
        Process.Start(new ProcessStartInfo(Path.Combine(target, "VedomyjVPN.exe")) { WorkingDirectory = target });
        return 0;
    }

    static void Extract(string target)
    {
        string root = Path.GetFullPath(target).TrimEnd('\\') + "\\";
        using (Stream res = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.zip"))
        using (ZipArchive zip = new ZipArchive(res, ZipArchiveMode.Read))
        {
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string name = entry.FullName.Replace('/', '\\');
                const string top = "VedomyjVPN\\"; // корневая папка внутри архива
                if (name.StartsWith(top, StringComparison.OrdinalIgnoreCase))
                {
                    name = name.Substring(top.Length);
                }
                if (name.Length == 0 || name.StartsWith("data\\", StringComparison.OrdinalIgnoreCase))
                {
                    continue; // свои настройки и подписки не трогаем
                }
                string path = Path.GetFullPath(Path.Combine(target, name));
                if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    continue; // защита от путей вида ..\
                }
                if (name.EndsWith("\\"))
                {
                    Directory.CreateDirectory(path);
                    continue;
                }
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                entry.ExtractToFile(path, true);
            }
        }
    }

    static void Shortcut(string lnk, string exe, string dir)
    {
        try
        {
            Type t = Type.GetTypeFromProgID("WScript.Shell");
            dynamic shell = Activator.CreateInstance(t);
            dynamic s = shell.CreateShortcut(lnk);
            s.TargetPath = exe;
            s.WorkingDirectory = dir;
            s.IconLocation = exe + ",0";
            s.Description = "VEDOMYJ VPN";
            s.Save();
        }
        catch (Exception)
        {
            // без ярлыка программа всё равно работает
        }
    }

    static void Register(string target, string exe)
    {
        using (RegistryKey k = Registry.CurrentUser.CreateSubKey(UninstallKey))
        {
            k.SetValue("DisplayName", "VEDOMYJ VPN");
            k.SetValue("DisplayVersion", Version);
            k.SetValue("Publisher", "VEDOMYJ VPN");
            k.SetValue("DisplayIcon", exe);
            k.SetValue("InstallLocation", target);
            k.SetValue("UninstallString", "\"" + Path.Combine(target, "Uninstall.exe") + "\" /uninstall");
            k.SetValue("NoModify", 1, RegistryValueKind.DWord);
            k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            k.SetValue("EstimatedSize", (int)(FolderSize(target) / 1024), RegistryValueKind.DWord);
        }
    }

    static long FolderSize(string dir)
    {
        long total = 0;
        try
        {
            foreach (string f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            {
                total += new FileInfo(f).Length;
            }
        }
        catch (Exception) { }
        return total;
    }

    // ---------- удаление ----------

    static int Uninstall(string target, bool quiet, bool fromTemp)
    {
        string self = Assembly.GetExecutingAssembly().Location;
        if (!fromTemp && self.StartsWith(target, StringComparison.OrdinalIgnoreCase))
        {
            // файл, который сейчас работает, удалить нельзя — запускаем копию из временной папки
            string tmp = Path.Combine(Path.GetTempPath(), "VedomyjVPN-uninstall.exe");
            File.Copy(self, tmp, true);
            Process.Start(tmp, "/uninstall /fromtemp" + (quiet ? " /quiet" : ""));
            return 0;
        }
        if (!quiet && MessageBox.Show(
                T("Удалить VEDOMYJ VPN вместе с настройками и подписками?", "Remove VEDOMYJ VPN with its settings and subscriptions?"),
                "VEDOMYJ VPN", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
        {
            return 2;
        }
        CloseRunning(target);
        using (RegistryKey run = Registry.CurrentUser.OpenSubKey(RunKey, true))
        {
            if (run != null && run.GetValue("VedomyjVPN") != null) run.DeleteValue("VedomyjVPN", false);
        }
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "VEDOMYJ VPN.lnk"));
        TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "VEDOMYJ VPN.lnk"));
        Registry.CurrentUser.DeleteSubKeyTree(UninstallKey, false);
        for (int i = 0; i < 5 && Directory.Exists(target); i++)
        {
            try { Directory.Delete(target, true); }
            catch (Exception) { Thread.Sleep(1000); }
        }
        if (!quiet)
        {
            MessageBox.Show(T("VEDOMYJ VPN удалён.", "VEDOMYJ VPN has been removed."), "VEDOMYJ VPN",
                            MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        if (fromTemp)
        {
            // временная копия удалит себя после выхода
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe",
                "/c ping -n 3 127.0.0.1 >nul & del /q \"" + self + "\"");
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(psi);
        }
        return 0;
    }

    static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch (Exception) { }
    }

    // ---------- закрыть работающую программу ----------

    static void CloseRunning(string target)
    {
        // вежливо: через её интерфейс — так она отключит VPN и вернёт настройки прокси Windows
        try
        {
            string info = File.ReadAllText(Path.Combine(target, @"data\ui.json"));
            Match port = Regex.Match(info, "\"port\"\\s*:\\s*(\\d+)");
            Match token = Regex.Match(info, "\"token\"\\s*:\\s*\"([^\"]+)\"");
            if (port.Success && token.Success)
            {
                using (WebClient wc = new WebClient())
                {
                    wc.Proxy = null;
                    wc.Headers.Add("X-Token", token.Groups[1].Value);
                    wc.Headers.Add("Content-Type", "application/json");
                    wc.UploadString("http://127.0.0.1:" + port.Groups[1].Value + "/api/action", "POST",
                                    "{\"action\":\"quit\",\"args\":{}}");
                }
            }
        }
        catch (Exception) { }
        string root = Path.GetFullPath(target).TrimEnd('\\') + "\\";
        bool killed = false;
        for (int i = 0; i < 30; i++)
        {
            bool any = false;
            foreach (Process p in Process.GetProcesses())
            {
                string file = "";
                try { file = p.MainModule.FileName; } catch (Exception) { continue; }
                if (file.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    any = true;
                    if (i >= 20)
                    {
                        try { p.Kill(); killed = true; } catch (Exception) { }
                    }
                }
            }
            if (!any) break;
            Thread.Sleep(500);
        }
        if (killed)
        {
            // программу пришлось закрыть силой — выключаем прокси Windows, если он указывал на неё
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", true))
            {
                if (k != null)
                {
                    object server = k.GetValue("ProxyServer");
                    if (server != null && server.ToString().StartsWith("127.0.0.1:"))
                    {
                        k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                    }
                }
            }
        }
    }

    static Form ShowWait(string text, bool quiet)
    {
        if (quiet) return null;
        Form f = new Form();
        f.Text = "VEDOMYJ VPN";
        f.FormBorderStyle = FormBorderStyle.FixedDialog;
        f.StartPosition = FormStartPosition.CenterScreen;
        f.ClientSize = new Size(360, 90);
        f.MaximizeBox = false;
        f.MinimizeBox = false;
        f.ControlBox = false;
        Label l = new Label();
        l.Text = text;
        l.AutoSize = false;
        l.TextAlign = ContentAlignment.MiddleCenter;
        l.Dock = DockStyle.Fill;
        l.Font = new Font("Segoe UI", 11f);
        f.Controls.Add(l);
        f.Show();
        f.Refresh();
        Application.DoEvents();
        return f;
    }
}
