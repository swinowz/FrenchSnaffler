using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SnaffCore
{
    /// <summary>
    /// Alternate credentials for network access, like "runas /netonly": the
    /// local identity is kept, SMB and LDAP authenticate as the given account.
    /// Works from a machine outside the domain and needs no local logon right.
    /// Based on SnaffCon/Snaffler#167, which used an interactive logon instead.
    /// </summary>
    public static class RunAsCredentials
    {
        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_WINNT50 = 3;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string user, string domain, string password,
            int logonType, int logonProvider, out SafeAccessTokenHandle token);

        /// <summary>Splits DOMAIN\user or user@domain; falls back to the given domain.</summary>
        public static (string Domain, string User) Split(string account, string fallbackDomain)
        {
            if (string.IsNullOrWhiteSpace(account)) throw new ArgumentException("empty account name");
            int slash = account.IndexOf('\\');
            if (slash > 0) return (account.Substring(0, slash), account.Substring(slash + 1));
            int at = account.LastIndexOf('@');
            if (at > 0) return (account.Substring(at + 1), account.Substring(0, at));
            return (string.IsNullOrWhiteSpace(fallbackDomain) ? "." : fallbackDomain, account);
        }

        /// <summary>
        /// Token to pass to WindowsIdentity.RunImpersonated. The password is not
        /// checked here: a NEW_CREDENTIALS logon only uses it on first network access.
        /// </summary>
        public static SafeAccessTokenHandle Logon(string domain, string user, string password)
        {
            if (!LogonUser(user, domain, password ?? "", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, out SafeAccessTokenHandle token))
            {
                int error = Marshal.GetLastWin32Error();
                token.Dispose();
                throw new Win32Exception(error, $"LogonUser failed for {domain}\\{user}");
            }
            return token;
        }

        /// <summary>Reads a password from the console without echoing it.</summary>
        public static string PromptPassword(string account)
        {
            if (Console.IsInputRedirected) return Console.In.ReadLine() ?? "";
            Console.Write($"Password for {account}: ");
            var chars = new System.Text.StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (chars.Length > 0) chars.Length--; continue; }
                if (!char.IsControl(key.KeyChar)) chars.Append(key.KeyChar);
            }
            Console.WriteLine();
            return chars.ToString();
        }
    }
}
