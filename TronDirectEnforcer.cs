// TRON direct administrator-controller Windows firewall adapter. Requires .NET Framework 4.0+ / Windows.
// No PowerShell, script-policy changes, shell execution, keys, inbox, or AI code.
// ADMIN_CONTROLLER_ATTESTATION is a privileged assertion, not proof of AI review.
using System;
using System.Collections;
using System.Diagnostics;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

internal sealed class Reject : Exception { public Reject(string text) : base(text) {} }

internal static class TronDirectEnforcer {
    const string InstallName = "TRON-Direct-Enforcement-v1";
    const string ExeName = "TronDirectEnforcer.exe";
    const int MaxDocument = 65536;
    const int MaxRecords = 10000;
    const int MaxRules = 16;
    const long MaxProgramBytes = 536870912;
    const string SystemSid = "S-1-5-18";
    const string AdminSid = "S-1-5-32-544";
    static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), InstallName);
    static readonly string StagingRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TRON-Direct-Enforcement-Staging-v1");
    static readonly string StateRoot = Path.Combine(Root, "state");
    static readonly string ClockPath = Path.Combine(Root, "clock-high-water.json");
    static readonly string HistoryPath = Path.Combine(Root, "history-high-water.json");
    static readonly string Self = Path.GetFullPath(Assembly.GetExecutingAssembly().Location);
    static readonly string Exe = Path.Combine(Root, ExeName);
    static Dictionary<string,object> Config;
    static dynamic Policy;
    static bool CacheRules;
    static Dictionary<string,List<dynamic>> RuleCache;
    static DateTime Now { get { return DateTime.UtcNow; } }

    [STAThread]
    static int Main(string[] args) {
        try {
            if(args.Length<1)throw new Reject("USAGE: install CONFIG | install-cleanup | arm | disarm | status | inspect BASE64 | apply BASE64 | cleanup | rollback NONCE");
            string command=args[0];
            if(command=="install"){NeedAdmin();NeedArgs(args,2);Install(args[1]);return 0;}
            NeedInstalled();
            Config=Object(Json.Parse(ReadBounded(Path.Combine(Root,"config.json"))));CheckConfig(Config);NeedMachine();
            if(command=="status"){NeedArgs(args,1);Policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));Status();return 0;}
            // SYSTEM may only perform cleanup. Every other mutation/inspection
            // requires the configured authenticated elevated interactive user.
            if(command=="cleanup")NeedAdmin();else NeedController();
            using(FileStream gate=new FileStream(Path.Combine(Root,"operation.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)){
                Config=Object(Json.Parse(ReadBounded(Path.Combine(Root,"config.json"))));CheckConfig(Config);NeedMachine();
                if(command!="cleanup")NeedController();
                if(command=="inspect"){
                    NeedArgs(args,2);Authorization a=VerifyAttestation(DecodeArgument(args[1]),true);NeedClockHealthy(false);
                    using(FileStream program=CheckProgram(a.Program,a.ProgramSha256)){
                        Print(new Dictionary<string,object>{{"status","VALID_ADMIN_ATTESTATION_NO_FIREWALL_CHANGE"},{"authority","ADMIN_CONTROLLER_ATTESTATION"},{"nonce",a.Nonce},{"deviceId",a.Device},{"expiresAt",Stamp(a.Expires)}});
                    }
                    return 0;
                }
                if(command=="install-cleanup"){NeedArgs(args,1);InstallCleanup();return 0;}
                Policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));
                if(command=="cleanup"){NeedArgs(args,1);Cleanup();Atomic(Path.Combine(Root,"cleanup-health.json"),new Dictionary<string,object>{{"completedAt",Stamp(Now)}});Print(new Dictionary<string,object>{{"status","CLEANUP_ONLY_OK"}});return 0;}
                if(command=="rollback"){NeedArgs(args,2);Rollback(args[1]);return 0;}
                if(command=="disarm"){NeedArgs(args,1);Disarm();return 0;}
                if(command=="arm"){NeedArgs(args,1);Arm();return 0;}
                if(command=="apply"){NeedArgs(args,2);RunAttested(DecodeArgument(args[1]));return 0;}
                throw new Reject("UNKNOWN_COMMAND");
            }
        }catch(Exception e){
            Print(new Dictionary<string,object>{{"status","REJECTED"},{"error",e is Reject?e.Message:e.GetType().Name+": "+e.Message}});return 1;
        }finally{if(Policy!=null&&Marshal.IsComObject(Policy))Marshal.FinalReleaseComObject(Policy);}
    }

    static void NeedArgs(string[] args,int count) { if(args.Length != count) throw new Reject("BAD_ARGUMENT_COUNT"); }
    static void NeedAdmin() {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) && identity.User.Value != SystemSid) throw new Reject("ADMINISTRATOR_REQUIRED");
    }
    static void NeedInstalled() {
        if (!String.Equals(Self, Exe, StringComparison.OrdinalIgnoreCase)) throw new Reject("RUN_PROTECTED_INSTALLED_EXECUTABLE");
        if (!Directory.Exists(Root)) throw new Reject("NOT_INSTALLED");
        NoReparse(Root);
        CheckAcl(Root, true); CheckAcl(Exe, false); CheckAcl(Path.Combine(Root,"config.json"), false); CheckAcl(StateRoot, true);
    }
    static void NeedMachine() {
        string guid = Convert.ToString(Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null), CultureInfo.InvariantCulture).ToLowerInvariant();
        if (guid != Str(Config,"machineGuid")) throw new Reject("MACHINE_IDENTITY_MISMATCH");
    }
    static DirectorySecurity PrivateDirectorySecurity() {
        DirectorySecurity d = new DirectorySecurity();
        d.SetAccessRuleProtection(true,false);
        d.SetOwner(new SecurityIdentifier(AdminSid));
        foreach (string sid in new[]{SystemSid,AdminSid}) d.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        if(Config!=null)d.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Str(Config,"controllerSid")),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        return d;
    }
    static void CheckAcl(string path, bool directory) {
        NoReparse(path);
        FileSystemSecurity acl = directory ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
        RawSecurityDescriptor rawAcl=new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(),0);
        if(rawAcl.DiscretionaryAcl==null||(rawAcl.ControlFlags&ControlFlags.DiscretionaryAclPresent)==0)throw new Reject("NULL_DACL_FORBIDDEN");
        string owner = acl.GetOwner(typeof(SecurityIdentifier)).Value;
        if (owner != AdminSid && owner != SystemSid) throw new Reject("UNTRUSTED_OWNER");
        FileSystemRights readonlyRights = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;
        foreach (FileSystemAccessRule r in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
            if (r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & ~readonlyRights) != 0 && r.IdentityReference.Value != AdminSid && r.IdentityReference.Value != SystemSid) throw new Reject("UNTRUSTED_WRITABLE_INSTALLATION");
        }
    }
    static void NoReparse(string path) {
        string p = Path.GetFullPath(path);
        while (!String.IsNullOrEmpty(p)) {
            if ((File.Exists(p)||Directory.Exists(p)) && (File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0) throw new Reject("REPARSE_PATH_FORBIDDEN");
            string parent = Path.GetDirectoryName(p);
            if (parent==p) break;
            p=parent;
        }
    }
    static string ReadBounded(string path) {
        NoReparse(path);
        using (FileStream f = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            if(f.Length < 2 || f.Length > MaxDocument) throw new Reject("DOCUMENT_SIZE_INVALID");
            byte[] data = new byte[(int)f.Length]; int n=0;
            while(n<data.Length){int got=f.Read(data,n,data.Length-n);if(got==0)throw new Reject("TRUNCATED_DOCUMENT");n+=got;}
            return Utf8.GetString(data);
        }
    }
    static void WriteDurable(string path, string value, bool append) {
        NoReparse(path);
        using(FileStream f = new FileStream(path,append?FileMode.Append:FileMode.CreateNew,FileAccess.Write,FileShare.Read)) {
            byte[] b=Utf8.GetBytes(value); f.Write(b,0,b.Length); f.Flush(true);
        }
    }
    static void Atomic(string path, object value) {
        string temp=Path.Combine(Path.GetDirectoryName(path),"tmp-"+Guid.NewGuid().ToString("N"));
        try { WriteDurable(temp,Json.Stringify(value),false); if(File.Exists(path)){CheckAcl(path,false);File.Replace(temp,path,null);}else File.Move(temp,path); CheckAcl(path,false); }
        finally { if(File.Exists(temp)) File.Delete(temp); }
    }
    static void Audit(string eventName, string nonce, string detail) {
        string path=Path.Combine(Root,"audit.jsonl");
        if(File.Exists(path)) CheckAcl(path,false);
        WriteDurable(path,Json.Stringify(new Dictionary<string,object>{{"at",Stamp(Now)},{"event",eventName},{"nonce",nonce},{"detail",detail}})+"\n",true);
    }
    static void Print(object o) { Console.WriteLine(Json.Stringify(o)); }

    static void Install(string configPath) {
        if (Directory.Exists(Root)||File.Exists(Root)) throw new Reject("INSTALL_PATH_EXISTS_REFUSING_OVERWRITE");
        NeedProtectedStage(Self);NeedProtectedStage(Path.GetFullPath(configPath));
        NoReparse(Path.GetDirectoryName(Root));
        Dictionary<string,object> c=Object(Json.Parse(ReadBounded(configPath)));
        CheckConfig(c);
        if(Bool(c,"authorizationEnabled"))throw new Reject("INITIAL_INSTALL_MUST_BE_DISABLED");
        Config=c;NeedMachine();NeedController();
        Directory.CreateDirectory(Root,PrivateDirectorySecurity());
        // No deletion of a failed installation: retain evidence and require review.
        Directory.CreateDirectory(StateRoot,PrivateDirectorySecurity());
        File.Copy(Self,Exe,false);
        Atomic(Path.Combine(Root,"config.json"),c);
        // Initialize once only. Missing/corrupt clock state is never silently rebuilt.
        Atomic(ClockPath,new Dictionary<string,object>{{"schemaVersion",1},{"maxObservedUtc",Stamp(Now)}});
        // A fresh empty journal is initialized only here. Later absence or
        // truncation must never silently reset consumed authorization history.
        WriteDurable(Path.Combine(Root,"authorizations.jsonl"),"",false);
        Atomic(HistoryPath,new Dictionary<string,object>{{"schemaVersion",1},{"minimumJournalRecords",0}});
        NeedProtectedFilesAfterInstall();
        Audit("INSTALLED_DISABLED",null,"No firewall or scheduled task changed");
        Print(new Dictionary<string,object>{{"status","INSTALLED_DISABLED"},{"path",Exe}});
    }
    static void NeedProtectedStage(string path) {
        if(!path.StartsWith(StagingRoot+"\\",StringComparison.OrdinalIgnoreCase))throw new Reject("PROTECTED_STAGING_REQUIRED_BEFORE_ELEVATION");
        CheckAcl(path,false);string parent=Path.GetDirectoryName(path);
        while(parent.Length>=StagingRoot.Length){CheckAcl(parent,true);if(parent.Equals(StagingRoot,StringComparison.OrdinalIgnoreCase))return;parent=Path.GetDirectoryName(parent);}
        throw new Reject("PROTECTED_STAGING_REQUIRED_BEFORE_ELEVATION");
    }
    static void NeedProtectedFilesAfterInstall(){CheckAcl(Root,true);CheckAcl(StateRoot,true);CheckAcl(Exe,false);CheckAcl(Path.Combine(Root,"config.json"),false);CheckAcl(ClockPath,false);CheckAcl(HistoryPath,false);CheckAcl(Path.Combine(Root,"authorizations.jsonl"),false);}
    static void CheckConfig(Dictionary<string,object> c) {
        Keys(c,"schemaVersion","authority","deviceId","machineGuid","controllerSid","policyHash","maxAuthorizationSeconds","authorizationEnabled","protectedAddresses","protectedProgramPaths","allowedProgramPaths","programSha256Pins");
        if(Int(c,"schemaVersion")!=1||Str(c,"authority")!="ADMIN_CONTROLLER_ATTESTATION")throw new Reject("CONFIG_AUTHORITY_VERSION");
        Uuid(Str(c,"deviceId"));Uuid(Str(c,"machineGuid"));Hash(Str(c,"policyHash"));Bool(c,"authorizationEnabled");
        if(Int(c,"maxAuthorizationSeconds")<1||Int(c,"maxAuthorizationSeconds")>3600)throw new Reject("CONFIG_TTL_LIMIT");
        string sid=Str(c,"controllerSid");if(!Regex.IsMatch(sid,@"\AS-1-5-21-(?:[0-9]+-){3}[0-9]+\z")||new SecurityIdentifier(sid).Value!=sid)throw new Reject("PINNED_LOCAL_CONTROLLER_SID_REQUIRED");
        foreach(object x in List(c,"protectedAddresses"))PublicIp(AsString(x));
        foreach(object x in List(c,"protectedProgramPaths"))CanonicalProgram(AsString(x));
        if(c["allowedProgramPaths"]!=null)foreach(object x in Array(c["allowedProgramPaths"]))CanonicalProgram(AsString(x));
        if(List(c,"protectedAddresses").Count>1024||List(c,"protectedProgramPaths").Count>128)throw new Reject("CONFIG_LIST_TOO_LARGE");
        Dictionary<string,object> pins=Object(c["programSha256Pins"]);if(pins.Count>128)throw new Reject("PROGRAM_PIN_LIMIT");
        HashSet<string> paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string,object> pin in pins){CanonicalProgram(pin.Key);Hash(AsString(pin.Value));if(!paths.Add(pin.Key))throw new Reject("DUPLICATE_PROGRAM_PIN");}
    }
    internal static void ControllerGate(bool elevated,bool authenticated,string actualSid,string pinnedSid,int sessionId) {
        if(!elevated)throw new Reject("ADMINISTRATOR_REQUIRED");
        if(!authenticated||actualSid==SystemSid||actualSid!=pinnedSid||sessionId<=0)throw new Reject("LIVE_PINNED_ADMIN_CONTROLLER_REQUIRED");
    }
    static void NeedController() {
        using(WindowsIdentity identity=WindowsIdentity.GetCurrent()){
            bool elevated=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            ControllerGate(elevated,identity.IsAuthenticated,identity.User.Value,Str(Config,"controllerSid"),Process.GetCurrentProcess().SessionId);
        }
    }
    internal static string DecodeArgument(string text) {
        // Bound the complete raw argument before allocation or JSON parsing.
        if(text==null||text.Length>24576)throw new Reject("ATTESTATION_ARGUMENT_TOO_LARGE");
        byte[] raw=Base64(text);if(raw.Length<2||raw.Length>16384)throw new Reject("ATTESTATION_ARGUMENT_SIZE_INVALID");
        string value=Utf8.GetString(raw);object parsed=Json.Parse(value);
        if(Json.Stringify(parsed)!=value)throw new Reject("CANONICAL_ATTESTATION_ARGUMENT_REQUIRED");
        return value;
    }

    sealed class Authorization {
        public string Attestation, Nonce, Device, Candidate, RuleHash, EvidenceHash, PolicyHash, Program, ProgramSha256, Address, Name, Description;
        public DateTime Issued, Expires;
        public List<string> Invocations=new List<string>();
    }
    static Authorization VerifyAttestation(string raw,bool current) {
        Dictionary<string,object> p=Object(Json.Parse(raw));if(Json.Stringify(p)!=raw)throw new Reject("CANONICAL_ATTESTATION_REQUIRED");
        Keys(p,"schemaVersion","kind","authority","category","confirmationStatus","deviceId","candidateDigest","ruleHash","evidenceHash","localEvidenceHash","threatIntelEvidenceHash","policyHash","attestationContextHash","issuedAt","expiresAt","nonce","reviews","rule");
        if(Int(p,"schemaVersion")!=1||Str(p,"kind")!="TRON_DIRECT_BLOCK_ATTESTATION"||Str(p,"authority")!="ADMIN_CONTROLLER_ATTESTATION")throw new Reject("ATTESTATION_AUTHORITY_MISMATCH");
        if(!new[]{"MALWARE_C2","PHISHING","EXFILTRATION"}.Contains(Str(p,"category"))||Str(p,"confirmationStatus")!="CONFIRMED_TECHNICAL_THREAT")throw new Reject("CONFIRMED_TECHNICAL_CATEGORY_REQUIRED");
        Authorization a=new Authorization();a.Attestation=raw;a.Device=Str(p,"deviceId");Uuid(a.Device);
        if(a.Device!=Str(Config,"deviceId"))throw new Reject("WRONG_DEVICE");
        a.Nonce=Str(p,"nonce");Hash(a.Nonce);a.Candidate=Str(p,"candidateDigest");Hash(a.Candidate);a.RuleHash=Str(p,"ruleHash");Hash(a.RuleHash);a.EvidenceHash=Str(p,"evidenceHash");Hash(a.EvidenceHash);a.PolicyHash=Str(p,"policyHash");Hash(a.PolicyHash);
        if(current&&a.PolicyHash!=Str(Config,"policyHash"))throw new Reject("POLICY_MISMATCH");
        string local=Str(p,"localEvidenceHash"),intel=Str(p,"threatIntelEvidenceHash");Hash(local);Hash(intel);if(local==intel)throw new Reject("DISTINCT_ORIGINAL_EVIDENCE_REQUIRED");
        a.Issued=Date(Str(p,"issuedAt"));a.Expires=Date(Str(p,"expiresAt"));
        if(a.Expires<=a.Issued||(a.Expires-a.Issued).TotalSeconds>3600)throw new Reject("TTL_INVALID");
        if(current&&(a.Expires-a.Issued).TotalSeconds>Int(Config,"maxAuthorizationSeconds"))throw new Reject("POLICY_TTL_EXCEEDED");
        if(current&&(a.Issued>Now||a.Expires<=Now||a.Issued<=Now.AddHours(-1)))throw new Reject("ATTESTATION_NOT_CURRENT");
        Dictionary<string,object> reviews=Object(p["reviews"]);Keys(reviews,"codex","chatgptController");
        Dictionary<string,object> codex=Object(reviews["codex"]),chatgpt=Object(reviews["chatgptController"]);
        Keys(codex,"channel","witnessed","decision","invocationId","receiptHash","contextHash","completedAt");
        Keys(chatgpt,"channel","witnessed","decision","decisionHash","contextHash","completedAt");
        if(Str(codex,"channel")!="CODEX"||Str(chatgpt,"channel")!="CURRENT_CHATGPT_CONTROLLER"||!Bool(codex,"witnessed")||!Bool(chatgpt,"witnessed")||Str(codex,"decision")!="CONFIRM_BLOCK"||Str(chatgpt,"decision")!="CONFIRM_BLOCK")throw new Reject("BOTH_WITNESSED_CONFIRMATIONS_REQUIRED");
        string id=Str(codex,"invocationId");if(!Regex.IsMatch(id,@"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\z"))throw new Reject("CODEX_INVOCATION_ID_INVALID");
        Hash(Str(codex,"receiptHash"));Hash(Str(chatgpt,"decisionHash"));a.Invocations.Add("CODEX:"+id);a.Invocations.Add("CHATGPT_ATTESTATION:"+Str(chatgpt,"decisionHash"));
        foreach(Dictionary<string,object> review in new[]{codex,chatgpt}){DateTime at=Date(Str(review,"completedAt"));if(at>a.Issued||at<=a.Issued.AddHours(-1))throw new Reject("STALE_REVIEW_ATTESTATION");}
        Dictionary<string,object> rule=Object(p["rule"]);Keys(rule,"action","deviceId","direction","protocol","remoteAddress","programPath","programSha256","scope");
        if(Str(rule,"action")!="BLOCK"||Str(rule,"deviceId")!=a.Device||Str(rule,"direction")!="OUTBOUND"||Str(rule,"protocol")!="ANY"||Str(rule,"scope")!="SINGLE_DEVICE")throw new Reject("RULE_SCOPE_INVALID");
        a.Address=Str(rule,"remoteAddress");PublicIp(a.Address);
        if(current&&List(Config,"protectedAddresses").Any(x=>AsString(x)==a.Address))throw new Reject("PROTECTED_MANAGEMENT_ADDRESS");
        a.Program=CanonicalProgram(Str(rule,"programPath"));a.ProgramSha256=Str(rule,"programSha256");Hash(a.ProgramSha256);
        if(Sha(Utf8.GetBytes(Json.Stringify(rule)))!=a.RuleHash)throw new Reject("RULE_HASH_MISMATCH");
        string contextHash=ContextHash(p);Hash(Str(p,"attestationContextHash"));Hash(Str(codex,"contextHash"));Hash(Str(chatgpt,"contextHash"));
        if(contextHash!=Str(p,"attestationContextHash")||contextHash!=Str(codex,"contextHash")||contextHash!=Str(chatgpt,"contextHash"))throw new Reject("REVIEW_CONTEXT_BINDING_MISMATCH");
        a.Name="TRONdirect1-"+a.Nonce;a.Description="TRONDIRECT1;"+a.Device+";"+a.Nonce+";"+Stamp(a.Expires)+";"+a.RuleHash;
        return a;
    }
    internal static string ContextHash(Dictionary<string,object> p) {
        Dictionary<string,object> context=new Dictionary<string,object>();
        foreach(string key in new[]{"candidateDigest","category","confirmationStatus","deviceId","evidenceHash","localEvidenceHash","threatIntelEvidenceHash","policyHash","ruleHash","expiresAt","nonce"})context.Add(key,Str(p,key));
        context.Add("programSha256",Str(Object(p["rule"]),"programSha256"));
        return Sha(Utf8.GetBytes(Json.Stringify(context)));
    }
    static string CanonicalProgram(string input) {
        if(input.Length<8||input.Length>240||!Regex.IsMatch(input,@"\A[A-Za-z]:\\")||input.IndexOf('/')>=0||input.IndexOf(':',2)>=0||input.IndexOfAny(new[]{'*','?','"','\0','\r','\n','%','~'})>=0)throw new Reject("PROGRAM_PATH_INVALID");
        string full=Path.GetFullPath(input);
        if(!String.Equals(full,input,StringComparison.Ordinal)||!input.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))throw new Reject("PROGRAM_PATH_NOT_CANONICAL_EXE");
        foreach(string segment in input.Substring(3).Split('\\'))if(segment.Length==0||segment.EndsWith(" ")||segment.EndsWith("."))throw new Reject("PROGRAM_PATH_SEGMENT_INVALID");
        return full;
    }
    static FileStream CheckProgram(string program,string attestedHash) {
        CanonicalProgram(program);NoReparse(program);
        if(!File.Exists(program))throw new Reject("PROGRAM_NOT_PRESENT");
        string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\')+"\\";
        if(program.StartsWith(windows,StringComparison.OrdinalIgnoreCase)||program.StartsWith(Root+"\\",StringComparison.OrdinalIgnoreCase))throw new Reject("PROTECTED_SYSTEM_PROGRAM");
        string name=Path.GetFileNameWithoutExtension(program).ToLowerInvariant();
        string[] prohibited={"node","nodejs","powershell","pwsh","cmd","wscript","cscript","conhost","mstsc","sshd","ssh","codex","desktopcommander","desktop-commander","tronenforcer","trondirectenforcer"};
        if(prohibited.Contains(name)||name.Contains("desktopcommander")||name.Contains("desktop-commander")||name.StartsWith("codex"))throw new Reject("PROTECTED_MANAGEMENT_PROGRAM");
        if(List(Config,"protectedProgramPaths").Any(x=>String.Equals(AsString(x),program,StringComparison.OrdinalIgnoreCase)))throw new Reject("PROTECTED_MANAGEMENT_PROGRAM");
        if(Config["allowedProgramPaths"]!=null&&!Array(Config["allowedProgramPaths"]).Any(x=>String.Equals(AsString(x),program,StringComparison.OrdinalIgnoreCase)))throw new Reject("PROGRAM_NOT_IN_OPTIONAL_ALLOWLIST");
        string expected=ProgramPin(Object(Config["programSha256Pins"]),program);
        if(expected!=attestedHash)throw new Reject("ATTESTED_PROGRAM_PIN_MISMATCH");
        // Keep the handle open through native creation, denying writes/deletion
        // of this executable while its verified identity is being consumed.
        FileStream stream=new FileStream(program,FileMode.Open,FileAccess.Read,FileShare.Read);
        try{NoReparse(program);VerifyProgramHash(stream,expected);return stream;}catch{stream.Dispose();throw;}
    }
    internal static string ProgramPin(Dictionary<string,object> pins,string program) {
        List<KeyValuePair<string,object>> matches=pins.Where(x=>String.Equals(x.Key,program,StringComparison.OrdinalIgnoreCase)).ToList();
        if(matches.Count!=1)throw new Reject("EXACT_PROGRAM_SHA256_PIN_REQUIRED");
        string expected=AsString(matches[0].Value);Hash(expected);return expected;
    }
    internal static void VerifyProgramHash(Stream program,string expected) {
        Hash(expected);if(!program.CanRead||!program.CanSeek||program.Length<1||program.Length>MaxProgramBytes)throw new Reject("PROGRAM_SIZE_INVALID");
        program.Position=0;string actual;using(SHA256 h=SHA256.Create())actual=BitConverter.ToString(h.ComputeHash(program)).Replace("-","").ToLowerInvariant();
        if(!String.Equals(actual,expected,StringComparison.Ordinal))throw new Reject("PROGRAM_SHA256_CHANGED");
        program.Position=0;
    }
    static bool ProgramIdentityCurrent(string program,string hash) {try{using(FileStream file=CheckProgram(program,hash))return true;}catch(Exception){return false;}}

    internal static DateTime CheckedClockAdvance(DateTime now,DateTime highWater) {
        if(now.Kind!=DateTimeKind.Utc||highWater.Kind!=DateTimeKind.Utc)throw new Reject("UTC_CLOCK_REQUIRED");
        if(now<highWater)throw new Reject("CLOCK_MOVED_BACKWARDS");return now;
    }
    static DateTime ReadClockHighWater() {
        if(!File.Exists(ClockPath))throw new Reject("INITIALIZED_CLOCK_STATE_REQUIRED");
        CheckAcl(ClockPath,false);Dictionary<string,object> c=Object(Json.Parse(ReadBounded(ClockPath)));Keys(c,"schemaVersion","maxObservedUtc");
        if(Int(c,"schemaVersion")!=1)throw new Reject("CLOCK_STATE_VERSION");return Date(Str(c,"maxObservedUtc"));
    }
    static void NeedClockHealthy(bool advance) {
        DateTime high=ReadClockHighWater(),now=CheckedClockAdvance(Now,high);
        if(advance&&now>high)Atomic(ClockPath,new Dictionary<string,object>{{"schemaVersion",1},{"maxObservedUtc",Stamp(now)}});
    }
    static void PublicIp(string address) {
        if(!Regex.IsMatch(address,@"\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z"))throw new Reject("SINGLE_CANONICAL_IPV4_REQUIRED");
        int[] b=address.Split('.').Select(x=>Int32.Parse(x,CultureInfo.InvariantCulture)).ToArray();
        if(b.Any(x=>x>255))throw new Reject("IPV4_INVALID");
        if(b[0]==0||b[0]==10||b[0]==127||b[0]>=224||(b[0]==100&&b[1]>=64&&b[1]<=127)||(b[0]==169&&b[1]==254)||(b[0]==172&&b[1]>=16&&b[1]<=31)||(b[0]==192&&b[1]==168)||(b[0]==192&&b[1]==0)||(b[0]==192&&b[1]==88&&b[2]==99)||(b[0]==198&&(b[1]==18||b[1]==19))||(b[0]==198&&b[1]==51&&b[2]==100)||(b[0]==203&&b[1]==0&&b[2]==113))throw new Reject("PRIVATE_RESERVED_OR_PROTECTED_ADDRESS");
    }

    sealed class Record { public string Path; public Dictionary<string,object> Data; public Authorization Auth; public string Phase {get{return Str(Data,"phase");}} }
    static int ReadHistoryMinimum() {
        if(!File.Exists(HistoryPath))throw new Reject("INITIALIZED_HISTORY_CHECKPOINT_REQUIRED");
        CheckAcl(HistoryPath,false);Dictionary<string,object> h=Object(Json.Parse(ReadBounded(HistoryPath)));Keys(h,"schemaVersion","minimumJournalRecords");
        int minimum=Int(h,"minimumJournalRecords");
        if(Int(h,"schemaVersion")!=1||minimum<0||minimum>MaxRecords)throw new Reject("HISTORY_CHECKPOINT_INVALID");
        return minimum;
    }
    internal static void CheckHistoryContinuity(int minimum,bool journalPresent,ISet<string> journalNonces,IEnumerable<string> stateNonces) {
        if(minimum<0||minimum>MaxRecords)throw new Reject("HISTORY_CHECKPOINT_INVALID");
        if(!journalPresent)throw new Reject("INITIALIZED_AUTHORIZATION_JOURNAL_REQUIRED");
        if(journalNonces==null||stateNonces==null)throw new Reject("HISTORY_SNAPSHOT_REQUIRED");
        if(journalNonces.Count<minimum)throw new Reject("AUTHORIZATION_HISTORY_REGRESSED");
        foreach(string nonce in stateNonces)if(!journalNonces.Contains(nonce))throw new Reject("STATE_RECORD_MISSING_JOURNAL_ENTRY");
    }
    static List<Record> Records() { List<string> errors;List<Record> records=ReadRecords(out errors);if(errors.Count!=0)throw new Reject("LEDGER_RECOVERY_REQUIRED:"+String.Join(",",errors.ToArray()));return records; }
    static List<Record> ReadRecords(out List<string> errors) {
        errors=new List<string>();Dictionary<string,Record> found=new Dictionary<string,Record>(StringComparer.Ordinal);
        int? minimum=null;try{minimum=ReadHistoryMinimum();}catch(Exception e){errors.Add("HISTORY_CHECKPOINT:"+e.Message);}
        string journal=Path.Combine(Root,"authorizations.jsonl");
        bool journalPresent=File.Exists(journal);
        if(journalPresent){try{
            CheckAcl(journal,false);int lines=0;
            using(StreamReader reader=new StreamReader(new FileStream(journal,FileMode.Open,FileAccess.Read,FileShare.ReadWrite),Utf8,false,4096)){
                while(!reader.EndOfStream){
                    if(++lines>MaxRecords){errors.Add("JOURNAL_CAPACITY");break;}
                    StringBuilder line=new StringBuilder();bool overflow=false;int ch;
                    while((ch=reader.Read())!=-1&&ch!='\n'){if(line.Length<MaxDocument)line.Append((char)ch);else overflow=true;}
                    if(overflow){errors.Add("JOURNAL_LINE_TOO_LONG");continue;}
                    try{
                        Authorization a=VerifyAttestation(line.ToString(),false);
                        if(found.ContainsKey(a.Nonce)){if(found[a.Nonce].Auth.Attestation!=a.Attestation)throw new Reject("JOURNAL_NONCE_CONFLICT");continue;}
                        found.Add(a.Nonce,new Record{Path=Path.Combine(StateRoot,a.Nonce+".json"),Auth=a,Data=new Dictionary<string,object>{{"attestation",a.Attestation},{"phase","RESERVED"},{"updatedAt",Stamp(a.Issued)}}});
                    }catch(Exception){errors.Add("JOURNAL_LINE_INVALID_"+lines.ToString(CultureInfo.InvariantCulture));}
                }
            }
        }catch(Exception e){errors.Add("JOURNAL_UNAVAILABLE:"+e.GetType().Name);}
        }
        HashSet<string> journalNonces=new HashSet<string>(found.Keys,StringComparer.Ordinal);
        List<string> stateNonces=new List<string>();
        string[] files=new string[0];try{files=Directory.GetFiles(StateRoot,"*.json",SearchOption.TopDirectoryOnly);}catch(Exception e){errors.Add("STATE_DIRECTORY_UNAVAILABLE:"+e.GetType().Name);}
        if(files.Length>MaxRecords){errors.Add("STATE_CAPACITY");files=files.Take(MaxRecords).ToArray();}
        foreach(string path in files){
            try{
                CheckAcl(path,false);Dictionary<string,object> r=Object(Json.Parse(ReadBounded(path)));Keys(r,"attestation","phase","updatedAt");
                string phase=Str(r,"phase");if(!new[]{"RESERVED","ACTIVE","REMOVED","FAILED"}.Contains(phase))throw new Reject("CORRUPT_LEDGER_PHASE");Date(Str(r,"updatedAt"));
                Authorization a=VerifyAttestation(Str(r,"attestation"),false);if(Path.GetFileName(path)!=a.Nonce+".json")throw new Reject("CORRUPT_LEDGER_FILENAME");
                stateNonces.Add(a.Nonce);
                if(found.ContainsKey(a.Nonce)&&found[a.Nonce].Auth.Attestation!=a.Attestation)throw new Reject("STATE_JOURNAL_CONFLICT");
                found[a.Nonce]=new Record{Path=path,Data=r,Auth=a};
            }catch(Exception){errors.Add("STATE_RECORD_INVALID_"+Path.GetFileName(path));}
        }
        try{CheckHistoryContinuity(minimum??0,journalPresent,journalNonces,stateNonces);}catch(Exception e){errors.Add("HISTORY_CONTINUITY:"+e.Message);}
        return found.Values.ToList();
    }
    static void SetPhase(Record r,string phase) { r.Data["phase"]=phase;r.Data["updatedAt"]=Stamp(Now);Atomic(r.Path,r.Data); }
    static string Group {get{return "TRON.Direct.Enforcement.v1."+Str(Config,"deviceId");}}
    static List<dynamic> NamedRules(string name) {
        if(CacheRules){
            if(RuleCache==null){RuleCache=new Dictionary<string,List<dynamic>>(StringComparer.Ordinal);foreach(dynamic item in Policy.Rules){string key=(string)item.Name;if(!RuleCache.ContainsKey(key))RuleCache.Add(key,new List<dynamic>());RuleCache[key].Add(item);}}
            return RuleCache.ContainsKey(name)?RuleCache[name]:new List<dynamic>();
        }
        List<dynamic> rules=new List<dynamic>();
        foreach(dynamic rule in Policy.Rules) { if((string)rule.Name==name) rules.Add(rule); }
        return rules;
    }
    static bool Exact(dynamic rule,Authorization a) {
        string remote=Convert.ToString(rule.RemoteAddresses,CultureInfo.InvariantCulture);
        bool ip=remote==a.Address||remote==a.Address+"/255.255.255.255"||remote==a.Address+"/32";
        object interfaces=rule.Interfaces;bool noInterfaces=interfaces==null || (interfaces is System.Array&&((System.Array)interfaces).Length==0);
        return (string)rule.Name==a.Name&&(string)rule.Description==a.Description&&(string)rule.Grouping==Group&&(bool)rule.Enabled&&(int)rule.Direction==2&&(int)rule.Action==0&&(int)rule.Protocol==256&&(int)rule.Profiles==Int32.MaxValue&&ip&&(string)rule.LocalAddresses=="*"&&noInterfaces&&String.Equals((string)rule.ApplicationName,a.Program,StringComparison.OrdinalIgnoreCase)&&String.IsNullOrEmpty((string)rule.ServiceName)&&((string)rule.InterfaceTypes).Equals("All",StringComparison.OrdinalIgnoreCase)&&!(bool)rule.EdgeTraversal;
    }
    static bool IsPresentExact(Authorization a) {
        List<dynamic> match=NamedRules(a.Name);if(match.Count>1)throw new Reject("DUPLICATE_OWN_RULE_NAME");
        if(match.Count==0)return false;
        if(!Exact(match[0],a))throw new Reject("OWN_RULE_READBACK_MISMATCH");return true;
    }
    static void RemoveExact(Authorization a,string reason) {
        RuleCache=null;
        if(!IsPresentExact(a))return;
        Exception auditError=null;try{Audit("REMOVE_INTENT",a.Nonce,reason);}catch(Exception e){auditError=e;}
        Policy.Rules.Remove(a.Name);
        RuleCache=null;
        if(NamedRules(a.Name).Count!=0)throw new Reject("OWN_RULE_REMOVAL_UNVERIFIED");
        try{Audit("REMOVED",a.Nonce,reason);}catch(Exception e){auditError=e;}
        // Expiry removal takes precedence over an append-log failure. Surface the
        // failure after exact removal and prohibit new creation until health recovers.
        if(auditError!=null)throw new Reject("RULE_REMOVED_AUDIT_WRITE_FAILED");
    }
    internal static string ActiveRemovalReason(bool clockFault,DateTime expires,DateTime now,string address,IEnumerable<object> protectedAddresses) {
        if(clockFault)return "clock unavailable or regressed; remove exact own rule";
        if(expires<=now)return "authorization expired";
        if(protectedAddresses.Any(x=>AsString(x)==address))return "destination is now protected by current configuration";
        return null;
    }
    static void Cleanup() {
        CacheRules=true;RuleCache=null;try{
        List<string> errors;List<Record> records=ReadRecords(out errors);
        bool clockFault=false;try{NeedClockHealthy(true);}catch(Exception e){clockFault=true;errors.Add("CLOCK_HEALTH:"+e.Message);}
        Dictionary<string,bool> identities=new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);
        foreach(Record r in records) { try{
            if(r.Phase=="RESERVED") { RemoveExact(r.Auth,"crash reconciliation of durable reservation");SetPhase(r,"FAILED");Audit("RESERVATION_RECONCILED",r.Auth.Nonce,"No new rule authorized"); }
            else if(r.Phase=="ACTIVE") {
                string removalReason=ActiveRemovalReason(clockFault,r.Auth.Expires,Now,r.Auth.Address,List(Config,"protectedAddresses"));
                if(removalReason!=null){RemoveExact(r.Auth,removalReason);SetPhase(r,"REMOVED");}
                else if(!IsPresentExact(r.Auth)){SetPhase(r,"REMOVED");Audit("RULE_MISSING",r.Auth.Nonce,"External removal detected");}
                else {
                    if(!identities.ContainsKey(r.Auth.Program+"|"+r.Auth.ProgramSha256))identities.Add(r.Auth.Program+"|"+r.Auth.ProgramSha256,ProgramIdentityCurrent(r.Auth.Program,r.Auth.ProgramSha256));
                    if(!identities[r.Auth.Program+"|"+r.Auth.ProgramSha256]){RemoveExact(r.Auth,"pinned program identity unavailable or changed");SetPhase(r,"REMOVED");}
                }
            } else if(IsPresentExact(r.Auth)) { RemoveExact(r.Auth,"inactive ledger record reconciled"); }
        }catch(Exception e){errors.Add(r.Auth.Nonce+":"+e.Message);}
        }
        if(errors.Count!=0)throw new Reject("CLEANUP_PARTIAL_ERROR:"+String.Join(",",errors.ToArray()));
        }finally{CacheRules=false;RuleCache=null;}
    }
    static void CheckFirewall() {
        if((int)Policy.LocalPolicyModifyState!=0)throw new Reject("LOCAL_FIREWALL_POLICY_NOT_EFFECTIVE");
        int profiles=(int)Policy.CurrentProfileTypes;
        if(profiles==0)throw new Reject("NO_ACTIVE_FIREWALL_PROFILE");
        foreach(int bit in new[]{1,2,4})if((profiles&bit)!=0 && !(bool)Policy.FirewallEnabled[bit])throw new Reject("ACTIVE_FIREWALL_PROFILE_DISABLED");
    }
    static void RunAttested(string raw) {
        NeedController();if(!Bool(Config,"authorizationEnabled"))throw new Reject("ENFORCEMENT_DISABLED");
        NeedClockHealthy(true);Authorization a=VerifyAttestation(raw,true);
        using(FileStream program=CheckProgram(a.Program,a.ProgramSha256)) {
        NeedCleanupHealthy();CheckFirewall();Cleanup();
        List<Record> previous=Records();
        Record same=ReplayGate(a,previous);
        if(same!=null){
            if(same.Phase=="ACTIVE"&&same.Auth.Attestation==a.Attestation&&IsPresentExact(a)){Print(new Dictionary<string,object>{{"status","ALREADY_ACTIVE"},{"nonce",a.Nonce}});return;}
            throw new Reject("NONCE_ALREADY_RESERVED");
        }
        if(NamedRules(a.Name).Count!=0)throw new Reject("RULE_NAME_ALREADY_EXISTS");
        Record record=new Record{Path=Path.Combine(StateRoot,a.Nonce+".json"),Auth=a,Data=new Dictionary<string,object>{{"attestation",a.Attestation},{"phase","RESERVED"},{"updatedAt",Stamp(Now)}}};
        string journal=Path.Combine(Root,"authorizations.jsonl");if(File.Exists(journal))CheckAcl(journal,false);
        // Commit the minimum history size first. An interrupted append leaves
        // a detectable recovery condition; no rule can precede this boundary.
        Atomic(HistoryPath,new Dictionary<string,object>{{"schemaVersion",1},{"minimumJournalRecords",previous.Count+1}});
        WriteDurable(journal,a.Attestation+"\n",true);
        Atomic(record.Path,record.Data);Audit("RESERVED",a.Nonce,a.Candidate);
        try {
            dynamic rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule",true));
            rule.Name=a.Name;rule.Description=a.Description;rule.Grouping=Group;
            rule.Protocol=256;rule.Direction=2;rule.Action=0;rule.Profiles=Int32.MaxValue;
            rule.ApplicationName=a.Program;rule.RemoteAddresses=a.Address;rule.LocalAddresses="*";rule.InterfaceTypes="All";rule.EdgeTraversal=false;rule.Enabled=true;
            // Persisted reservation precedes the only code path that creates a rule.
            NeedClockHealthy(true);
            if(a.Expires<=Now)throw new Reject("AUTHORIZATION_EXPIRED_BEFORE_CREATE");
            Policy.Rules.Add(rule);
            if(!IsPresentExact(a))throw new Reject("CREATED_RULE_MISSING");
            NeedClockHealthy(true);
            if(a.Expires<=Now)throw new Reject("AUTHORIZATION_EXPIRED_DURING_CREATE");
            CheckFirewall();SetPhase(record,"ACTIVE");Audit("ACTIVE",a.Nonce,a.RuleHash);
            Print(new Dictionary<string,object>{{"status","ACTIVE_ADMIN_ATTESTATION_VERIFIED"},{"authority","ADMIN_CONTROLLER_ATTESTATION"},{"nonce",a.Nonce},{"ruleName",a.Name},{"expiresAt",Stamp(a.Expires)},{"scope","EXACT_PROGRAM_SINGLE_PUBLIC_IPV4_OUTBOUND"}});
        } catch {
            // Exact match only. Never delete unrelated or modified rules by prefix.
            RemoveExact(a,"creation failed; rollback only this administrator-attested nonce");SetPhase(record,"FAILED");throw;
        }
        }
    }
    // Pure replay gate is separated from native mutation for direct contract tests.
    // A same-nonce ACTIVE match still requires live exact firewall readback in RunAttested.
    static Record ReplayGate(Authorization a,List<Record> previous) {
        Record same=previous.FirstOrDefault(r=>r.Auth.Nonce==a.Nonce);
        if(same!=null){if(same.Phase=="ACTIVE"&&same.Auth.Attestation==a.Attestation)return same;throw new Reject("NONCE_ALREADY_RESERVED");}
        if(previous.Count>=MaxRecords)throw new Reject("REPLAY_LEDGER_FULL");
        if(previous.Any(r=>r.Auth.Candidate==a.Candidate||r.Auth.Invocations.Intersect(a.Invocations).Any()))throw new Reject("CANDIDATE_OR_INVOCATION_REPLAY");
        if(previous.Count(r=>r.Phase=="ACTIVE")>=MaxRules)throw new Reject("MAXIMUM_ACTIVE_RULES_REACHED");
        return null;
    }
    static void Rollback(string nonce) {
        Hash(nonce);List<string> errors;Record r=ReadRecords(out errors).FirstOrDefault(x=>x.Auth.Nonce==nonce);if(r==null)throw new Reject("NO_OWN_AUTHORIZATION_FOR_NONCE");
        RemoveExact(r.Auth,"explicit administrator rollback");SetPhase(r,"REMOVED");
        if(errors.Count!=0)throw new Reject("ROLLBACK_REMOVED_RULE_LEDGER_RECOVERY_REQUIRED");
        Print(new Dictionary<string,object>{{"status","ROLLBACK_VERIFIED"},{"nonce",nonce}});
    }
    static void Disarm() {
        Config["authorizationEnabled"]=false;Atomic(Path.Combine(Root,"config.json"),Config);
        List<string> errors;List<Record> records=ReadRecords(out errors);
        try{Audit("DISARMED",null,"New rule creation disabled");}catch(Exception e){errors.Add(e.Message);}
        foreach(Record r in records){try{RemoveExact(r.Auth,"administrator disarm");if(r.Phase!="REMOVED")SetPhase(r,"REMOVED");}catch(Exception e){errors.Add(r.Auth.Nonce+":"+e.Message);}}
        if(errors.Count!=0)throw new Reject("DISARMED_WITH_CLEANUP_ERRORS:"+String.Join(",",errors.ToArray()));
        Print(new Dictionary<string,object>{{"status","DISARMED_OWN_RULES_REMOVED"}});
    }
    static void Arm() {
        if(Bool(Config,"authorizationEnabled"))throw new Reject("ALREADY_ARMED_USE_STATUS");
        NeedClockHealthy(true);NeedCleanupHealthy();CheckFirewall();Cleanup();
        CommitArming(
            delegate{Audit("ARM_INTENT",null,"Explicit live administrator-controller attestations only; no rule created by arming");},
            delegate{Config["authorizationEnabled"]=true;Atomic(Path.Combine(Root,"config.json"),Config);},
            delegate{Audit("ARMED",null,"Explicit live administrator-controller attestations only; no rule created by arming");},
            delegate{Config["authorizationEnabled"]=false;Atomic(Path.Combine(Root,"config.json"),Config);}
        );
        Print(new Dictionary<string,object>{{"status","ARMED_ADMIN_CONTROLLER_ONLY_NO_RULE_CREATED"},{"authority","ADMIN_CONTROLLER_ATTESTATION"}});
    }
    // Testable lifecycle sequencing without native mutation in the test harness.
    internal static void CommitArming(Action intent,Action enable,Action completed,Action disable) {
        intent();
        try{enable();completed();}
        catch(Exception failure){
            try{disable();}catch(Exception rollback){throw new Reject("ARM_FAILED_STATE_UNVERIFIED:"+failure.Message+":"+rollback.Message);}
            throw new Reject("ARM_FAILED_DISABLED:"+failure.Message);
        }
    }

    static string TaskName {get{return "TRON-Direct-Enforcement-v1-Cleanup-"+Str(Config,"deviceId");}}
    static dynamic TaskService(){dynamic service=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service",true));service.Connect();return service;}
    static dynamic GetCleanupTask(){dynamic service=TaskService();return service.GetFolder("\\").GetTask(TaskName);}
    static void InstallCleanup() {
        dynamic service=TaskService(), folder=service.GetFolder("\\");
        foreach(dynamic existing in folder.GetTasks(1))if(((string)existing.Name).Equals(TaskName,StringComparison.OrdinalIgnoreCase))throw new Reject("CLEANUP_TASK_EXISTS_REFUSING_OVERWRITE");
        dynamic task=service.NewTask(0);
        task.RegistrationInfo.Description="Remove expired or invalid exact owned TRON direct rules only; no apply, inbox, AI or shell.";
        task.Principal.UserId="SYSTEM";task.Principal.LogonType=5;task.Principal.RunLevel=1;
        task.Settings.Enabled=true;task.Settings.Hidden=true;task.Settings.StartWhenAvailable=true;task.Settings.DisallowStartIfOnBatteries=false;task.Settings.StopIfGoingOnBatteries=false;task.Settings.ExecutionTimeLimit="PT1M";task.Settings.MultipleInstances=2;
        dynamic trigger=task.Triggers.Create(1);trigger.StartBoundary=DateTime.Now.AddMinutes(1).ToString("s",CultureInfo.InvariantCulture);trigger.Enabled=true;trigger.Repetition.Interval="PT1M";trigger.Repetition.StopAtDurationEnd=false;
        dynamic action=task.Actions.Create(0);action.Path=Exe;action.Arguments="cleanup";action.WorkingDirectory=Root;
        folder.RegisterTaskDefinition(TaskName,task,2,"SYSTEM",null,5,"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;"+Str(Config,"controllerSid")+")");
        CheckCleanupDefinition(GetCleanupTask());Audit("CLEANUP_TASK_INSTALLED",null,TaskName);
        Print(new Dictionary<string,object>{{"status","CLEANUP_TASK_INSTALLED_WAIT_FOR_SUCCESSFUL_SCHEDULED_RUN"},{"task",TaskName}});
    }
    static void CheckCleanupDefinition(dynamic task) {
        dynamic d=task.Definition;
        if(!(bool)task.Enabled || !(bool)d.Settings.Enabled || (int)d.Actions.Count!=1 || (int)d.Triggers.Count!=1)throw new Reject("CLEANUP_TASK_SHAPE");
        dynamic action=d.Actions.Item(1), trigger=d.Triggers.Item(1);
        if((int)action.Type!=0 || !String.Equals((string)action.Path,Exe,StringComparison.OrdinalIgnoreCase) || (string)action.Arguments!="cleanup" || !String.Equals((string)action.WorkingDirectory,Root,StringComparison.OrdinalIgnoreCase))throw new Reject("CLEANUP_TASK_ACTION_MISMATCH");
        string user=(string)d.Principal.UserId;
        if((user!="SYSTEM"&&user!="S-1-5-18")||(int)d.Principal.LogonType!=5||(int)d.Principal.RunLevel!=1)throw new Reject("CLEANUP_TASK_PRINCIPAL_MISMATCH");
        if((int)trigger.Type!=1||!(bool)trigger.Enabled||(string)trigger.Repetition.Interval!="PT1M"||(bool)trigger.Repetition.StopAtDurationEnd||!String.IsNullOrEmpty((string)trigger.Repetition.Duration)||!String.IsNullOrEmpty((string)trigger.EndBoundary))throw new Reject("CLEANUP_TASK_SCHEDULE_MISMATCH");
        if((bool)d.Settings.DisallowStartIfOnBatteries||(bool)d.Settings.StopIfGoingOnBatteries||!(bool)d.Settings.StartWhenAvailable||(int)d.Settings.MultipleInstances!=2)throw new Reject("CLEANUP_TASK_SETTINGS_MISMATCH");
        RawSecurityDescriptor acl=new RawSecurityDescriptor((string)task.GetSecurityDescriptor(7));
        if(acl.Owner==null || (acl.Owner.Value!=AdminSid&&acl.Owner.Value!=SystemSid))throw new Reject("CLEANUP_TASK_OWNER_MISMATCH");
        if(acl.DiscretionaryAcl==null)throw new Reject("CLEANUP_TASK_NULL_DACL");
        const int readonlyTaskRights=unchecked((int)0x801200A9);
        foreach(GenericAce ace in acl.DiscretionaryAcl){CommonAce allow=ace as CommonAce;if(allow!=null&&allow.AceQualifier==AceQualifier.AccessAllowed&&allow.SecurityIdentifier.Value!=AdminSid&&allow.SecurityIdentifier.Value!=SystemSid&&(allow.SecurityIdentifier.Value!=Str(Config,"controllerSid")||(allow.AccessMask&~readonlyTaskRights)!=0))throw new Reject("CLEANUP_TASK_UNTRUSTED_ACCESS");}
    }
    static void NeedCleanupHealthy() {
        dynamic task=GetCleanupTask();CheckCleanupDefinition(task);
        DateTime last=((DateTime)task.LastRunTime).ToUniversalTime();
        if((int)task.LastTaskResult!=0||last<Now.AddMinutes(-3)||last>Now.AddSeconds(30))throw new Reject("CLEANUP_TASK_NOT_RECENTLY_SUCCESSFUL");
        string p=Path.Combine(Root,"cleanup-health.json");CheckAcl(p,false);
        Dictionary<string,object> health=Object(Json.Parse(ReadBounded(p)));Keys(health,"completedAt");DateTime at=Date(Str(health,"completedAt"));
        if(at<last.AddSeconds(-5)||at<Now.AddMinutes(-3)||at>Now.AddSeconds(30))throw new Reject("CLEANUP_HEARTBEAT_STALE");
    }
    static void Status() {
        bool cleanup=false,firewall=false,clock=false;string error=null,firewallError=null,clockError=null;
        try{NeedClockHealthy(false);clock=true;}catch(Exception e){clockError=e.Message;}
        try{NeedCleanupHealthy();cleanup=true;}catch(Exception e){error=e.Message;}
        try{CheckFirewall();firewall=true;}catch(Exception e){firewallError=e.Message;}
        List<Record> r=Records();
        int verified=0;bool rulesHealthy=true;
        foreach(Record rec in r.Where(x=>x.Phase=="ACTIVE")){try{if(rec.Auth.Expires>Now&&IsPresentExact(rec.Auth)&&ProgramIdentityCurrent(rec.Auth.Program,rec.Auth.ProgramSha256))verified++;else rulesHealthy=false;}catch(Exception){rulesHealthy=false;}}
        Print(new Dictionary<string,object>{{"status",Bool(Config,"authorizationEnabled")&&cleanup&&firewall&&clock&&rulesHealthy?"ARMED_ADMIN_CONTROLLER_ONLY":"DISABLED_OR_NOT_READY"},{"authorizationEnabled",Bool(Config,"authorizationEnabled")},{"deviceId",Str(Config,"deviceId")},{"cleanupHealthy",cleanup},{"cleanupError",error},{"firewallEffective",firewall},{"firewallError",firewallError},{"clockHealthy",clock},{"clockError",clockError},{"ownRulesHealthy",rulesHealthy},{"ledgerRecords",r.Count},{"activeLedgerRecords",r.Count(x=>x.Phase=="ACTIVE")},{"verifiedActiveRules",verified}});
    }

    static Dictionary<string,object> Object(object o){Dictionary<string,object>d=o as Dictionary<string,object>;if(d==null)throw new Reject("OBJECT_REQUIRED");return d;}
    static List<object> Array(object o){List<object>a=o as List<object>;if(a==null)throw new Reject("ARRAY_REQUIRED");return a;}
    static List<object> List(Dictionary<string,object> o,string key){return Array(o[key]);}
    static string AsString(object o){if(!(o is string))throw new Reject("STRING_REQUIRED");return (string)o;}
    static string Str(Dictionary<string,object> o,string key){return AsString(o[key]);}
    static bool Bool(Dictionary<string,object> o,string key){if(!(o[key] is bool))throw new Reject("BOOLEAN_REQUIRED");return (bool)o[key];}
    static int Int(Dictionary<string,object> o,string key){if(!(o[key] is long)||(long)o[key]>Int32.MaxValue||(long)o[key]<Int32.MinValue)throw new Reject("INTEGER_REQUIRED");return (int)(long)o[key];}
    static void Keys(Dictionary<string,object> d,params string[] keys){if(d.Count!=keys.Length||keys.Any(k=>!d.ContainsKey(k)))throw new Reject("EXACT_SCHEMA_KEYS_REQUIRED");}
    static void Hash(string s){if(!Regex.IsMatch(s,@"\A[0-9a-f]{64}\z"))throw new Reject("SHA256_LOWERCASE_HEX_REQUIRED");}
    static void Uuid(string s){if(!Regex.IsMatch(s,@"\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z")||s=="00000000-0000-0000-0000-000000000000")throw new Reject("CANONICAL_NONZERO_UUID_REQUIRED");}
    static DateTime Date(string s){DateTime d;if(!DateTime.TryParseExact(s,"yyyy-MM-dd'T'HH:mm:ss.fff'Z'",CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal,out d)||Stamp(d)!=s)throw new Reject("CANONICAL_UTC_TIMESTAMP_REQUIRED");return d;}
    static string Stamp(DateTime d){return d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'",CultureInfo.InvariantCulture);}
    static byte[] Base64(string s){if(s.Length==0||s.Length>MaxDocument||s.Length%4!=0||!Regex.IsMatch(s,@"\A[A-Za-z0-9+/]*={0,2}\z"))throw new Reject("CANONICAL_BASE64_REQUIRED");byte[] b=Convert.FromBase64String(s);if(Convert.ToBase64String(b)!=s)throw new Reject("CANONICAL_BASE64_REQUIRED");return b;}
    static string Sha(byte[] b){using(SHA256 h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(b)).Replace("-","").ToLowerInvariant();}

    // Strict JSON parser: rejects duplicate keys, excess depth, noninteger numbers,
    // trailing material, BOM, control characters and unpaired UTF-16 surrogates.
    internal static class Json {
        public static object Parse(string s){Reader r=new Reader(s);object o=r.Value(0);r.White();if(r.I!=s.Length)throw new Reject("JSON_TRAILING_DATA");return o;}
        public static string Stringify(object o){StringBuilder b=new StringBuilder();Write(b,o);return b.ToString();}
        static void Write(StringBuilder b,object o){
            if(o==null){b.Append("null");return;}if(o is bool){b.Append((bool)o?"true":"false");return;}if(o is long||o is int){b.Append(Convert.ToString(o,CultureInfo.InvariantCulture));return;}
            if(o is string){Quote(b,(string)o);return;}
            Dictionary<string,object>d=o as Dictionary<string,object>;if(d!=null){b.Append('{');bool first=true;foreach(string k in d.Keys.OrderBy(k=>k,StringComparer.Ordinal)){if(!first)b.Append(',');first=false;Quote(b,k);b.Append(':');Write(b,d[k]);}b.Append('}');return;}
            IEnumerable list=o as IEnumerable;if(list!=null){b.Append('[');bool first=true;foreach(object x in list){if(!first)b.Append(',');first=false;Write(b,x);}b.Append(']');return;}throw new Reject("JSON_UNSUPPORTED_VALUE");
        }
        static void Quote(StringBuilder b,string s){b.Append('"');foreach(char c in s){switch(c){case '"':b.Append("\\\"");break;case '\\':b.Append("\\\\");break;case '\b':b.Append("\\b");break;case '\f':b.Append("\\f");break;case '\n':b.Append("\\n");break;case '\r':b.Append("\\r");break;case '\t':b.Append("\\t");break;default:if(c<32)b.Append("\\u"+((int)c).ToString("x4"));else b.Append(c);break;}}b.Append('"');}
        sealed class Reader {
            readonly string S;public int I;public Reader(string s){if(s.Length>MaxDocument)throw new Reject("JSON_TOO_LARGE");S=s;}
            public void White(){while(I<S.Length&&(S[I]==' '||S[I]=='\r'||S[I]=='\n'||S[I]=='\t'))I++;}
            char Take(){if(I>=S.Length)throw new Reject("JSON_TRUNCATED");return S[I++];}
            void Need(char c){if(Take()!=c)throw new Reject("JSON_SYNTAX");}
            public object Value(int depth){if(depth>8)throw new Reject("JSON_DEPTH");White();if(I>=S.Length)throw new Reject("JSON_TRUNCATED");char c=S[I];
                if(c=='{'){I++;Dictionary<string,object>d=new Dictionary<string,object>(StringComparer.Ordinal);White();if(I<S.Length&&S[I]=='}'){I++;return d;}while(true){White();string k=String();if(d.ContainsKey(k))throw new Reject("JSON_DUPLICATE_KEY");White();Need(':');d.Add(k,Value(depth+1));White();char sep=Take();if(sep=='}')return d;if(sep!=',')throw new Reject("JSON_SYNTAX");}}
                if(c=='['){I++;List<object>a=new List<object>();White();if(I<S.Length&&S[I]==']'){I++;return a;}while(true){if(a.Count>=1024)throw new Reject("JSON_ARRAY_LIMIT");a.Add(Value(depth+1));White();char sep=Take();if(sep==']')return a;if(sep!=',')throw new Reject("JSON_SYNTAX");}}
                if(c=='"')return String();if(c=='t'){Literal("true");return true;}if(c=='f'){Literal("false");return false;}if(c=='n'){Literal("null");return null;}
                int start=I;if(c=='-')I++;if(I>=S.Length||S[I]<'0'||S[I]>'9')throw new Reject("JSON_SYNTAX");if(S[I]=='0')I++;else while(I<S.Length&&S[I]>='0'&&S[I]<='9')I++;long n;if(!Int64.TryParse(S.Substring(start,I-start),NumberStyles.AllowLeadingSign,CultureInfo.InvariantCulture,out n))throw new Reject("JSON_INTEGER_REQUIRED");return n;
            }
            void Literal(string text){foreach(char c in text)Need(c);}
            string String(){Need('"');StringBuilder b=new StringBuilder();while(true){char c=Take();if(c=='"')break;if(c<32)throw new Reject("JSON_CONTROL_CHARACTER");if(c=='\\'){c=Take();switch(c){case '"':case '\\':case '/':break;case 'b':c='\b';break;case 'f':c='\f';break;case 'n':c='\n';break;case 'r':c='\r';break;case 't':c='\t';break;case 'u':int code=0;for(int j=0;j<4;j++){char h=Take();int v=h>='0'&&h<='9'?h-'0':h>='a'&&h<='f'?h-'a'+10:h>='A'&&h<='F'?h-'A'+10:-1;if(v<0)throw new Reject("JSON_UNICODE_ESCAPE");code=code*16+v;}c=(char)code;break;default:throw new Reject("JSON_ESCAPE");}}b.Append(c);}string result=b.ToString();for(int k=0;k<result.Length;k++){if(Char.IsHighSurrogate(result[k])){if(k+1>=result.Length||!Char.IsLowSurrogate(result[++k]))throw new Reject("JSON_UNPAIRED_SURROGATE");}else if(Char.IsLowSurrogate(result[k]))throw new Reject("JSON_UNPAIRED_SURROGATE");}return result;}
        }
    }
}
