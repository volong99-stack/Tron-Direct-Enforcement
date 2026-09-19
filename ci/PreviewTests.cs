// Runs only refusal probes: no installation, firewall changes or scheduled tasks.
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

internal static class PreviewTests {
    sealed class Result { internal int Code; internal string Output; internal string Error; }
    static Result Run(string file, string args) {
        StringBuilder output = new StringBuilder(), error = new StringBuilder();
        using (Process process = new Process()) {
            process.StartInfo = new ProcessStartInfo(file, args) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(file)
            };
            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) {
                if (e.Data != null) lock(output) output.AppendLine(e.Data);
            };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) {
                if (e.Data != null) lock(error) error.AppendLine(e.Data);
            };
            process.Start(); process.BeginOutputReadLine(); process.BeginErrorReadLine();
            if (!process.WaitForExit(30000)) { process.Kill(); process.WaitForExit(); throw new Exception("TEST_PROCESS_TIMEOUT"); }
            process.WaitForExit();
            return new Result { Code = process.ExitCode, Output = output.ToString().Trim(), Error = error.ToString().Trim() };
        }
    }
    static int Main() {
        try {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                if (!identity.IsAuthenticated || identity.User.Value == "S-1-5-18" ||
                    new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new Exception("STANDARD_USER_TOKEN_REQUIRED");
            }
            string bin = AppDomain.CurrentDomain.BaseDirectory;
            Result pure = Run(Path.Combine(bin, "TronDirectEnforcerPureTests.exe"), "");
            Match summary = Regex.Match(pure.Output, "^\\{\"status\":\"PURE_TESTS_PASSED\",\"passed\":([0-9]+),\"nativeOperations\":false\\}$");
            if (pure.Code != 0 || pure.Error.Length != 0 || !summary.Success)
                throw new Exception("PURE_HARNESS_FAILED: " + pure.Output + " " + pure.Error);
            int count = Int32.Parse(summary.Groups[1].Value);
            if (count < 1) throw new Exception("NO_PURE_TESTS_EXECUTED");
            string native = Path.Combine(bin, "TronDirectEnforcer.exe");
            string[] arguments = { "install missing-test-config.json", "apply e30=", "arm", "disarm", "cleanup", "install-cleanup", "rollback invalid-nonce", "status" };
            for (int i = 0; i < arguments.Length; i++) {
                Result refusal = Run(native, arguments[i]);
                string expected = i == 0 ? "ADMINISTRATOR_REQUIRED" : "RUN_PROTECTED_INSTALLED_EXECUTABLE";
                if (refusal.Code != 1 || refusal.Error.Length != 0 ||
                    !refusal.Output.Contains("\"status\":\"REJECTED\"") ||
                    !refusal.Output.Contains("\"error\":\"" + expected + "\""))
                    throw new Exception("REFUSAL_PROBE_FAILED: " + arguments[i] + " " + refusal.Output);
            }
            Console.WriteLine("{\"status\":\"PREVIEW_TESTS_PASSED\",\"pureTestsPassed\":" + count +
                ",\"windowsRefusalTestsPassed\":" + arguments.Length +
                ",\"standardUserTokenVerified\":true,\"firewallRulesCreated\":false,\"installed\":false}");
            return 0;
        } catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
    }
}
