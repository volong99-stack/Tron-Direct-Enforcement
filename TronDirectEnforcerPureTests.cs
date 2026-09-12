// Compile with TronDirectEnforcer.cs and /main:TronDirectEnforcerPureTests.
// This harness performs no Windows, filesystem, scheduler or firewall operation.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;

internal static class TronDirectEnforcerPureTests {
    const string AbcHash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static int passed;
    const string Device="11111111-1111-4111-8111-111111111111";
    static string H(string text){using(SHA256 h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-","").ToLowerInvariant();}
    static string Stamp(DateTime date){return date.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'",System.Globalization.CultureInfo.InvariantCulture);}
    static Dictionary<string,object> Obj(object value){return (Dictionary<string,object>)value;}
    static object Validate(Dictionary<string,object> p,bool current){return typeof(TronDirectEnforcer).GetMethod("VerifyAttestation",BindingFlags.NonPublic|BindingFlags.Static).Invoke(null,new object[]{TronDirectEnforcer.Json.Stringify(p),current});}
    static Dictionary<string,object> Fixture(){
        DateTime issued=DateTime.UtcNow.AddMinutes(-1);
        Dictionary<string,object> rule=new Dictionary<string,object>{{"action","BLOCK"},{"deviceId",Device},{"direction","OUTBOUND"},{"protocol","ANY"},{"remoteAddress","1.1.1.1"},{"programPath",@"C:\Test\Controlled.exe"},{"programSha256",AbcHash},{"scope","SINGLE_DEVICE"}};
        Dictionary<string,object> p=new Dictionary<string,object>{{"schemaVersion",1},{"kind","TRON_DIRECT_BLOCK_ATTESTATION"},{"authority","ADMIN_CONTROLLER_ATTESTATION"},{"category","MALWARE_C2"},{"confirmationStatus","CONFIRMED_TECHNICAL_THREAT"},{"deviceId",Device},{"candidateDigest",H("invented offline candidate")},{"ruleHash",H(TronDirectEnforcer.Json.Stringify(rule))},{"evidenceHash",H("invented offline evidence set")},{"localEvidenceHash",H("invented local fixture")},{"threatIntelEvidenceHash",H("invented threat fixture")},{"policyHash",H("fixture policy")},{"issuedAt",Stamp(issued)},{"expiresAt",Stamp(issued.AddMinutes(5))},{"nonce",H("fixture nonce")},{"rule",rule}};
        string context=TronDirectEnforcer.ContextHash(p);p.Add("attestationContextHash",context);
        p.Add("reviews",new Dictionary<string,object>{
            {"codex",new Dictionary<string,object>{{"channel","CODEX"},{"witnessed",true},{"decision","CONFIRM_BLOCK"},{"invocationId","offline-test-invocation"},{"receiptHash",H("fixture receipt")},{"contextHash",context},{"completedAt",Stamp(issued.AddSeconds(-1))}}},
            {"chatgptController",new Dictionary<string,object>{{"channel","CURRENT_CHATGPT_CONTROLLER"},{"witnessed",true},{"decision","CONFIRM_BLOCK"},{"decisionHash",H("fixture controller decision")},{"contextHash",context},{"completedAt",Stamp(issued.AddSeconds(-1))}}}
        });return p;
    }
    static void DirectAuthorityTests(){
        const string sid="S-1-5-21-111-222-333-1001";
        TronDirectEnforcer.ControllerGate(true,true,sid,sid,1);Check(true,"pinned elevated authenticated session allowed");
        Rejects(delegate{TronDirectEnforcer.ControllerGate(false,true,sid,sid,1);},"ADMINISTRATOR_REQUIRED","ordinary user cannot create");
        Rejects(delegate{TronDirectEnforcer.ControllerGate(true,true,"S-1-5-18","S-1-5-18",1);},"LIVE_PINNED_ADMIN_CONTROLLER_REQUIRED","SYSTEM cannot create even if pinned");
        Rejects(delegate{TronDirectEnforcer.ControllerGate(true,true,sid,sid,0);},"LIVE_PINNED_ADMIN_CONTROLLER_REQUIRED","service session cannot create");
        Rejects(delegate{TronDirectEnforcer.ControllerGate(true,false,sid,sid,1);},"LIVE_PINNED_ADMIN_CONTROLLER_REQUIRED","unauthenticated token cannot create");
        Rejects(delegate{TronDirectEnforcer.ControllerGate(true,true,sid,sid+"0",1);},"LIVE_PINNED_ADMIN_CONTROLLER_REQUIRED","other administrator SID cannot create");
        string canonical="{\"a\":1}";
        Check(TronDirectEnforcer.DecodeArgument(Convert.ToBase64String(Encoding.UTF8.GetBytes(canonical)))==canonical,"canonical argument decodes");
        Rejects(delegate{TronDirectEnforcer.DecodeArgument(Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"a\":1,\"a\":2}")));},"JSON_DUPLICATE_KEY","ambiguous receipt JSON rejects");
        Rejects(delegate{TronDirectEnforcer.DecodeArgument(Convert.ToBase64String(Encoding.UTF8.GetBytes("{ \"a\":1}")));},"CANONICAL_ATTESTATION_ARGUMENT_REQUIRED","formatted noncanonical argument rejects");
        Rejects(delegate{TronDirectEnforcer.DecodeArgument(new string('A',24580));},"ATTESTATION_ARGUMENT_TOO_LARGE","oversized argument rejected before parsing");
        FieldInfo config=typeof(TronDirectEnforcer).GetField("Config",BindingFlags.Static|BindingFlags.NonPublic);
        config.SetValue(null,new Dictionary<string,object>{{"deviceId",Device},{"policyHash",H("fixture policy")},{"maxAuthorizationSeconds",600L},{"protectedAddresses",new List<object>()}});
        Check(Validate(Fixture(),true)!=null,"synthetic attestation structural validation only");
        Dictionary<string,object> p=Fixture();Obj(Obj(p["reviews"])["chatgptController"])["invocationId"]="invented-upstream-id";
        Rejects(delegate{Validate(p,true);},"EXACT_SCHEMA_KEYS_REQUIRED","ChatGPT upstream invocation ID is not accepted");
        p=Fixture();Obj(Obj(p["reviews"])["codex"])["witnessed"]=false;
        Rejects(delegate{Validate(p,true);},"BOTH_WITNESSED_CONFIRMATIONS_REQUIRED","missing witnessed review rejects");
        p=Fixture();Obj(Obj(p["reviews"])["chatgptController"])["decision"]="FLAG_ONLY";
        Rejects(delegate{Validate(p,true);},"BOTH_WITNESSED_CONFIRMATIONS_REQUIRED","uncertain controller decision rejects");
        p=Fixture();Obj(Obj(p["reviews"])["codex"])["contextHash"]=H("other context");
        Rejects(delegate{Validate(p,true);},"REVIEW_CONTEXT_BINDING_MISMATCH","review from another context rejects");
        p=Fixture();Obj(p["rule"])["programSha256"]=H("replacement executable");
        Rejects(delegate{Validate(p,true);},"RULE_HASH_MISMATCH","executable digest is bound by exact rule hash");
        p=Fixture();Obj(p["rule"])["remoteAddress"]="192.168.56.2";
        Rejects(delegate{Validate(p,true);},"PRIVATE_RESERVED_OR_PROTECTED_ADDRESS","private IPv4 destination rejects");
        p=Fixture();p["threatIntelEvidenceHash"]=p["localEvidenceHash"];
        Rejects(delegate{Validate(p,true);},"DISTINCT_ORIGINAL_EVIDENCE_REQUIRED","same source digest cannot impersonate two sources");
        p=Fixture();p["expiresAt"]=Stamp(DateTime.Parse((string)p["issuedAt"],null,System.Globalization.DateTimeStyles.AdjustToUniversal).AddSeconds(601));
        Rejects(delegate{Validate(p,true);},"POLICY_TTL_EXCEEDED","configured TTL enforced");
        p=Fixture();p["issuedAt"]=Stamp(DateTime.UtcNow.AddHours(-2));p["expiresAt"]=Stamp(DateTime.UtcNow.AddHours(-2).AddMinutes(5));
        Rejects(delegate{Validate(p,true);},"ATTESTATION_NOT_CURRENT","expired administrator attestation rejects");
        p=Fixture();p["issuedAt"]=Stamp(DateTime.UtcNow.AddMinutes(10));p["expiresAt"]=Stamp(DateTime.UtcNow.AddMinutes(15));
        Rejects(delegate{Validate(p,true);},"ATTESTATION_NOT_CURRENT","future administrator attestation rejects");
        p=Fixture();Obj(Obj(p["reviews"])["codex"])["completedAt"]=Stamp(DateTime.UtcNow.AddHours(-2));
        Rejects(delegate{Validate(p,true);},"STALE_REVIEW_ATTESTATION","stale witnessed review rejects");
        p=Fixture();p["evidenceHash"]=H("different original evidence");
        Rejects(delegate{Validate(p,true);},"REVIEW_CONTEXT_BINDING_MISMATCH","different evidence cannot reuse confirmation context");
        p=Fixture();p["expiresAt"]=Stamp(DateTime.Parse((string)p["expiresAt"],null,System.Globalization.DateTimeStyles.AdjustToUniversal).AddSeconds(1));
        Rejects(delegate{Validate(p,true);},"REVIEW_CONTEXT_BINDING_MISMATCH","changed expiry within TTL requires new review binding");
        p=Fixture();p["nonce"]=H("another nonce");
        Rejects(delegate{Validate(p,true);},"REVIEW_CONTEXT_BINDING_MISMATCH","changed nonce requires new review binding");
        p=Fixture();p["category"]="MANIPULATIVE_IDEAS";
        Rejects(delegate{Validate(p,true);},"CONFIRMED_TECHNICAL_CATEGORY_REQUIRED","content or idea filtering is unsupported");
        p=Fixture();Obj(config.GetValue(null))["policyHash"]=H("changed policy");
        Rejects(delegate{Validate(p,true);},"POLICY_MISMATCH","new apply rejects old policy");
        Check(Validate(p,false)!=null,"historical policy change does not strand exact cleanup");
        config.SetValue(null,null);
    }
    static void HistoryAndProtectionTests(){
        string first=H("first consumed authorization"),second=H("second consumed authorization");
        HashSet<string> empty=new HashSet<string>(),one=new HashSet<string>{first},two=new HashSet<string>{first,second};
        TronDirectEnforcer.CheckHistoryContinuity(0,true,empty,new string[0]);
        Check(true,"fresh install may have an initialized empty journal");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(0,false,empty,new string[0]);},"INITIALIZED_AUTHORIZATION_JOURNAL_REQUIRED","missing journal cannot impersonate a fresh installation");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(1,false,empty,new[]{first});},"INITIALIZED_AUTHORIZATION_JOURNAL_REQUIRED","missing journal with retained state is a recovery error");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(2,true,empty,new string[0]);},"AUTHORIZATION_HISTORY_REGRESSED","cleared journal and state cannot erase checkpointed consumption");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(2,true,one,new[]{first});},"AUTHORIZATION_HISTORY_REGRESSED","valid-prefix journal truncation is rejected");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(1,true,one,new[]{first,second});},"STATE_RECORD_MISSING_JOURNAL_ENTRY","state without matching original journal entry cannot authorize creation");
        TronDirectEnforcer.CheckHistoryContinuity(2,true,two,new string[0]);
        Check(true,"intact journal retains history when all per-request states require reconstruction");
        TronDirectEnforcer.CheckHistoryContinuity(1,true,two,new[]{first});
        Check(true,"extra durable journal reservation remains consumed before state completion");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(2,true,one,new[]{first});},"AUTHORIZATION_HISTORY_REGRESSED","checkpoint persisted before interrupted append fails closed");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(-1,true,empty,new string[0]);},"HISTORY_CHECKPOINT_INVALID","negative history checkpoint is not an empty default");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(10001,true,empty,new string[0]);},"HISTORY_CHECKPOINT_INVALID","over-capacity history checkpoint is rejected");
        Rejects(delegate{TronDirectEnforcer.CheckHistoryContinuity(0,true,null,new string[0]);},"HISTORY_SNAPSHOT_REQUIRED","unavailable journal snapshot is not empty history");
        DateTime now=new DateTime(2020,1,1,12,0,0,DateTimeKind.Utc),later=now.AddMinutes(5);
        List<object> protectedAddresses=new List<object>{"1.1.1.1"};
        Check(TronDirectEnforcer.ActiveRemovalReason(false,later,now,"1.1.1.1",protectedAddresses)=="destination is now protected by current configuration","newly protected public destination retires a still-current active rule");
        Check(TronDirectEnforcer.ActiveRemovalReason(false,later,now,"8.8.8.8",protectedAddresses)==null,"unrelated protected destination does not remove a different valid rule");
        Check(TronDirectEnforcer.ActiveRemovalReason(false,later,now,"1.1.1.1",new List<object>())==null,"unchanged unprotected destination retains a current rule");
        Check(TronDirectEnforcer.ActiveRemovalReason(false,now,now,"1.1.1.1",new List<object>())=="authorization expired","expiry remains exclusive at the exact deadline");
        Check(TronDirectEnforcer.ActiveRemovalReason(true,later,now,"1.1.1.1",new List<object>())=="clock unavailable or regressed; remove exact own rule","clock failure still requires exact active-rule removal");
    }
    static void Check(bool condition,string name){if(!condition)throw new Exception("FAILED:"+name);passed++;}
    static void Rejects(Action action,string expected,string name){
        try{action();}catch(Exception e){while(e is TargetInvocationException&&e.InnerException!=null)e=e.InnerException;if(!e.Message.StartsWith(expected,StringComparison.Ordinal))throw new Exception("FAILED:"+name+":"+e.Message);passed++;return;}
        throw new Exception("FAILED:"+name+":accepted");
    }
    public static int Main(){
        try{
            DirectAuthorityTests();
            HistoryAndProtectionTests();
            bool enabled=false;string order="";
            TronDirectEnforcer.CommitArming(delegate{order+="I";},delegate{enabled=true;order+="E";},delegate{order+="A";},delegate{enabled=false;order+="D";});
            Check(enabled&&order=="IEA","successful arming commits in order");

            enabled=false;order="";
            Rejects(delegate{TronDirectEnforcer.CommitArming(delegate{throw new IOException("intent unavailable");},delegate{enabled=true;order+="E";},delegate{order+="A";},delegate{enabled=false;order+="D";});},"intent unavailable","intent audit failure rejects");
            Check(!enabled&&order=="","intent failure leaves disabled without mutations");

            enabled=false;order="";
            Rejects(delegate{TronDirectEnforcer.CommitArming(delegate{order+="I";},delegate{throw new IOException("write failed before commit");},delegate{order+="A";},delegate{enabled=false;order+="D";});},"ARM_FAILED_DISABLED","enable write failure rejects");
            Check(!enabled&&order=="ID","enable write failure performs disable persistence");

            enabled=false;order="";
            Rejects(delegate{TronDirectEnforcer.CommitArming(delegate{order+="I";},delegate{enabled=true;order+="E";throw new IOException("write failed after commit");},delegate{order+="A";},delegate{enabled=false;order+="D";});},"ARM_FAILED_DISABLED","postcommit enable failure rejects");
            Check(!enabled&&order=="IED","postcommit enable failure restores disabled");

            enabled=false;order="";
            Rejects(delegate{TronDirectEnforcer.CommitArming(delegate{order+="I";},delegate{enabled=true;order+="E";},delegate{throw new IOException("audit locked");},delegate{enabled=false;order+="D";});},"ARM_FAILED_DISABLED","completion audit failure rejects");
            Check(!enabled&&order=="IED","completion audit failure restores disabled");

            enabled=false;
            Rejects(delegate{TronDirectEnforcer.CommitArming(delegate{},delegate{enabled=true;},delegate{throw new IOException("audit locked");},delegate{throw new IOException("storage unavailable");});},"ARM_FAILED_STATE_UNVERIFIED","failed disable is explicitly unverified");
            Check(enabled,"unverified failure never falsely claims disabled");

            DateTime high=new DateTime(2020,1,2,12,0,0,DateTimeKind.Utc);
            Check(TronDirectEnforcer.CheckedClockAdvance(high,high)==high,"equal clock allowed");
            Check(TronDirectEnforcer.CheckedClockAdvance(high.AddSeconds(1),high)==high.AddSeconds(1),"forward clock allowed");
            Rejects(delegate{TronDirectEnforcer.CheckedClockAdvance(high.AddTicks(-1),high);},"CLOCK_MOVED_BACKWARDS","single-tick rollback rejects");
            Rejects(delegate{TronDirectEnforcer.CheckedClockAdvance(high.AddHours(-2),high);},"CLOCK_MOVED_BACKWARDS","expired-capsule clock rollback rejects");
            Rejects(delegate{TronDirectEnforcer.CheckedClockAdvance(DateTime.SpecifyKind(high,DateTimeKind.Unspecified),high);},"UTC_CLOCK_REQUIRED","ambiguous local time rejects");

            Dictionary<string,object> pins=new Dictionary<string,object>{{@"C:\Apps\sample.exe",AbcHash}};
            Check(TronDirectEnforcer.ProgramPin(pins,@"c:\apps\SAMPLE.exe")==AbcHash,"case-insensitive exact native path pin");
            Rejects(delegate{TronDirectEnforcer.ProgramPin(pins,@"C:\Apps\other.exe");},"EXACT_PROGRAM_SHA256_PIN_REQUIRED","unknown executable rejects");
            pins.Add(@"c:\apps\sample.exe",AbcHash);
            Rejects(delegate{TronDirectEnforcer.ProgramPin(pins,@"C:\Apps\sample.exe");},"EXACT_PROGRAM_SHA256_PIN_REQUIRED","ambiguous duplicate pin rejects");

            using(MemoryStream original=new MemoryStream(Encoding.UTF8.GetBytes("abc"))){original.Position=2;TronDirectEnforcer.VerifyProgramHash(original,AbcHash);Check(original.Position==0,"matching complete executable resets held stream");}
            using(MemoryStream changed=new MemoryStream(Encoding.UTF8.GetBytes("abd"))){Rejects(delegate{TronDirectEnforcer.VerifyProgramHash(changed,AbcHash);},"PROGRAM_SHA256_CHANGED","replacement bytes reject");}
            using(MemoryStream empty=new MemoryStream()){Rejects(delegate{TronDirectEnforcer.VerifyProgramHash(empty,AbcHash);},"PROGRAM_SIZE_INVALID","empty program rejects");}
            using(MemoryStream original=new MemoryStream(Encoding.UTF8.GetBytes("abc"))){Rejects(delegate{TronDirectEnforcer.VerifyProgramHash(original,AbcHash.ToUpperInvariant());},"SHA256_LOWERCASE_HEX_REQUIRED","noncanonical hash pin rejects");}
            using(OversizeStream huge=new OversizeStream()){Rejects(delegate{TronDirectEnforcer.VerifyProgramHash(huge,AbcHash);},"PROGRAM_SIZE_INVALID","oversize program rejects before hashing");}

            Console.WriteLine("{\"status\":\"PURE_TESTS_PASSED\",\"passed\":"+passed+",\"nativeOperations\":false}");return 0;
        }catch(Exception e){Console.WriteLine("PURE_TEST_FAILURE:"+e.Message);return 1;}
    }
    sealed class OversizeStream:MemoryStream {public override long Length{get{return 536870913;}}}
}
