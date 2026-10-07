// WP-3 / AT-03-001/003/007/010/012. User-mode WFP API; no kernel driver.
// SDK layouts/constants: microsoft/win32metadata fwpmtypes.h, fwptypes.h, fwpmu.h.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace VPNTE.IPv6 {
  public sealed class Rule {
    public Guid Id;
    public string Role, AppId = "", Remote = "", Luid = "";
    public bool OriginalApp, Inbound, Boot;
    public bool Block { get { return Role == "block"; } }
    public string Signature { get { return Role + "|" + AppId + "|" + Remote + "|" + Luid + "|" + OriginalApp + "|" + Inbound + "|" + Boot; } }
  }
  // The same transaction/read-back code is executed against a fake engine in tests.
  public interface IEngine : IDisposable {
    void Begin(); void Commit(); void Abort(); void EnsureSublayer();
    Rule[] ReadOwned(); void Add(Rule rule); void Delete(Guid id);
  }
  public static class Policy {
    public static readonly Guid Sublayer = new Guid("fd44e2d2-94a0-4b6e-99c9-3d61dff1b418");
    public const string Marker = "VPNTE.IPv6.v1";
    public static string CanonicalRemote(string remote) {
      if (String.IsNullOrEmpty(remote)) return "";
      var parts = remote.Split('/'); IPAddress ip; int prefix;
      if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 ||
          parts[0].Contains("%") || !Int32.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 128) throw new ArgumentException("Invalid IPv6 scope");
      byte[] bytes = ip.GetAddressBytes();
      for (int bit = prefix; bit < 128; bit++) bytes[bit / 8] &= (byte)~(1 << (7 - bit % 8));
      return new IPAddress(bytes).ToString() + "/" + prefix;
    }
    public static void Validate(Rule[] rules, bool complete = true) {
      if (rules == null || rules.Length < 1 || rules.Length > 2048 || rules.Select(r => r.Id).Distinct().Count() != rules.Length ||
          rules.Any(r => r.Id == Guid.Empty) || (complete && (rules.Count(r => r.Block && !r.Inbound && !r.Boot) != 1 || rules.Count(r => r.Block && r.Inbound && !r.Boot) != 1 || rules.Count(r => r.Block && r.Boot) != 1))) throw new ArgumentException("Invalid IPv6 policy set");
      foreach (var r in rules) {
        r.AppId = r.AppId ?? ""; r.Remote = CanonicalRemote(r.Remote); r.Luid = r.Luid ?? "";
        ulong luid;
        if (r.AppId.Length > 32768 || r.AppId.Length % 2 != 0 || r.AppId.Any(c => !Uri.IsHexDigit(c)) ||
            (r.Luid != "" && (!UInt64.TryParse(r.Luid, out luid) || luid == 0))) throw new ArgumentException("Invalid app/interface scope");
        r.AppId = r.AppId.ToUpperInvariant();
        if (r.Boot && (r.Inbound || (r.Role != "block" && r.Role != "lan"))) throw new ArgumentException("Boot IPv6 must block external traffic until BFE starts");
        switch (r.Role) {
          case "block": if (r.AppId != "" || r.Remote != "" || r.Luid != "" || r.OriginalApp) throw new ArgumentException("Block must cover all IPv6"); break;
          case "lan": if (r.AppId != "" || r.Luid != "" || r.OriginalApp || !new[]{"::1/128","fc00::/7","fe80::/10","ff00::/8"}.Contains(r.Remote)) throw new ArgumentException("Invalid local scope"); break;
          case "tun": if (r.AppId != "" || r.Remote != "" || r.Luid == "" || r.OriginalApp) throw new ArgumentException("Invalid TUN scope"); break;
          case "vpn": if (r.AppId == "" || !r.Remote.EndsWith("/128") || r.Luid == "" || r.OriginalApp) throw new ArgumentException("VPN permit needs app, exact address and interface"); break;
          case "exception-app": if (r.AppId == "" || r.Remote != "" || r.Luid != "" || r.OriginalApp) throw new ArgumentException("Invalid user app exception"); break;
          case "exception-ip": if (r.AppId != "" || r.Remote == "" || r.Luid != "" || r.OriginalApp) throw new ArgumentException("Invalid user IP exception"); break;
          default: throw new ArgumentException("Unknown IPv6 rule role");
        }
      }
    }
    public static void AssertSame(Rule[] actual, Rule[] expected) {
      if (actual.Length != expected.Length || actual.Select(r => r.Id).Distinct().Count() != actual.Length ||
          actual.Any(r => !expected.Any(e => e.Id == r.Id && e.Signature == r.Signature))) throw new InvalidOperationException("IPv6 policy read-back mismatch");
    }
    public static void Apply(IEngine engine, Rule[] rules) {
      Validate(rules); engine.Begin();
      try {
        engine.EnsureSublayer();
        foreach (var old in engine.ReadOwned()) engine.Delete(old.Id);
        foreach (var rule in rules) engine.Add(rule);
        AssertSame(engine.ReadOwned(), rules);
        engine.Commit();
      } catch { engine.Abort(); throw; }
      AssertSame(engine.ReadOwned(), rules);
    }
    public static void Remove(IEngine engine) {
      engine.Begin();
      try {
        foreach (var rule in engine.ReadOwned()) engine.Delete(rule.Id);
        AssertSame(engine.ReadOwned(), new Rule[0]); engine.Commit();
      } catch { engine.Abort(); throw; }
      AssertSame(engine.ReadOwned(), new Rule[0]);
    }
  }
  public sealed class NativeEngine : IEngine {
    static readonly Guid Layer = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    static readonly Guid InboundLayer = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    static readonly Guid BootLayer = new Guid("a3b3ab6b-3564-488c-9117-f34e82142763");
    static readonly Guid RemoteKey = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid AppKey = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid OriginalAppKey = new Guid("0e6cd086-e1fb-4212-842f-8a9f993fb3f6");
    static readonly Guid InterfaceKey = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    const uint NotFound = 0x80320007;
    // A lower-priority block can be bypassed by a higher hard permit.
    // Our permits stay soft so foreign blocks can still restrict the VPN.
    const ushort SublayerWeight = 0xffff;
    IntPtr handle;
    bool checkingPriority;
    ushort actualSublayerWeight;
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string Name, Description; }
    [StructLayout(LayoutKind.Explicit, Size=16)] struct Value { [FieldOffset(0)] public uint Type; [FieldOffset(8)] public IntPtr Pointer; [FieldOffset(8)] public byte Byte; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid Key; public uint Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Explicit, Size=16)] struct Context { [FieldOffset(0)] public ulong Raw; [FieldOffset(0)] public Guid Key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
      public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob ProviderData;
      public Guid Layer, Sublayer; public Value Weight; public uint Count; public IntPtr Conditions; public Action Action;
      public Context Context; public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Sublayer { public Guid Key; public Display Display; public uint Flags; public IntPtr Provider; public Blob ProviderData; public ushort Weight; }
    [StructLayout(LayoutKind.Sequential)] struct EnumTemplate {
      public IntPtr Provider; public Guid Layer; public uint Type, Flags; public IntPtr Context;
      public uint Count; public IntPtr Conditions; public uint Actions; public IntPtr Callout;
    }
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr sublayer);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumeration);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumeration, uint size, out IntPtr entries, out uint count);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumeration);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file, out IntPtr appId);
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
    static void Check(uint error) { if (error != 0) throw new InvalidOperationException("WFP error 0x" + error.ToString("X8")); }
    static T Read<T>(IntPtr p) { return (T)Marshal.PtrToStructure(p, typeof(T)); }
    public NativeEngine() {
      if (IntPtr.Size != 8) throw new PlatformNotSupportedException("WFP helper requires x64");
      Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out handle));
    }
    public void Dispose() { if (handle != IntPtr.Zero) { Check(FwpmEngineClose0(handle)); handle = IntPtr.Zero; } }
    public void Begin() { Check(FwpmTransactionBegin0(handle, 0)); }
    public void Commit() { Check(FwpmTransactionCommit0(handle)); }
    public void Abort() { Check(FwpmTransactionAbort0(handle)); }
    public static string InterfaceLuid(string interfaceGuid) { Guid guid = new Guid(interfaceGuid); ulong luid; Check(ConvertInterfaceGuidToLuid(ref guid, out luid)); if (luid == 0) throw new InvalidOperationException("Interface not verified"); return luid.ToString(); }
    static byte[] Bytes(IntPtr pointer, int size) { if (pointer == IntPtr.Zero || size < 1 || size > 16384) throw new InvalidOperationException("Invalid WFP buffer"); var bytes = new byte[size]; Marshal.Copy(pointer, bytes, 0, size); return bytes; }
    static string ReadAppId(IntPtr pointer) { var blob = Read<Blob>(pointer); return BitConverter.ToString(Bytes(blob.Data, checked((int)blob.Size))).Replace("-", ""); }
    public static string AppId(string path) { IntPtr pointer = IntPtr.Zero; try { Check(FwpmGetAppIdFromFileName0(path, out pointer)); return ReadAppId(pointer); } finally { if (pointer != IntPtr.Zero) FwpmFreeMemory0(ref pointer); } }
    public void EnsureSublayer() { CheckSublayer(true); VerifyPriority(); }
    public void VerifyPriority() { checkingPriority=true; try { ReadOwned(); } finally { checkingPriority=false; } }
    static bool MayHardPermit(Filter filter) {
      // Deciding callouts can return PERMIT and clear ACTION_WRITE at runtime,
      // even without a static CLEAR_ACTION_RIGHT flag. Inspection cannot permit.
      return (filter.Flags & 0x20) == 0 &&
        ((filter.Action.Type == 0x1002 && (filter.Flags & 8) != 0) ||
          filter.Action.Type == 0x5003 || filter.Action.Type == 0x4005);
    }
    static bool HigherHardPermit(Filter filter, ushort weight, ushort ownWeight) {
      return weight >= ownWeight && MayHardPermit(filter) &&
        (filter.Layer == Layer || filter.Layer == InboundLayer || filter.Layer == BootLayer);
    }
    static bool FilterFlagsValid(uint flags, bool boot) {
      // Windows may add INDEXED (0x40); it changes lookup, not policy semantics.
      // Disabled is valid only for boot filters after the BFE transition.
      return (flags & ~(boot ? 0x60u : 0x40u)) == (boot ? 2u : 1u);
    }
    bool CheckSublayer(bool create) {
      Guid key = Policy.Sublayer; IntPtr pointer = IntPtr.Zero;
      try {
        uint error = FwpmSubLayerGetByKey0(handle, ref key, out pointer);
        if (error == NotFound) {
          if (!create) return false;
          var layer = new Sublayer { Key=key, Display=new Display { Name=Policy.Marker, Description=Policy.Marker }, Flags=1, Weight=SublayerWeight };
          Check(FwpmSubLayerAdd0(handle, ref layer, IntPtr.Zero));
          Check(FwpmSubLayerGetByKey0(handle, ref key, out pointer));
        } else Check(error);
        var actual = Read<Sublayer>(pointer);
        if (actual.Key != key || actual.Display.Name != Policy.Marker || actual.Display.Description != Policy.Marker || actual.Flags != 1 || actual.Weight == 0 || (actualSublayerWeight != 0 && actual.Weight != actualSublayerWeight) || actual.Provider != IntPtr.Zero || actual.ProviderData.Size != 0) throw new InvalidOperationException("Foreign WFP sublayer; unchanged");
        // BFE may return a lower weight when the requested priority is occupied.
        // Identity and priority safety are checked separately, against read-back.
        actualSublayerWeight=actual.Weight;
        return true;
      } finally { if (pointer != IntPtr.Zero) FwpmFreeMemory0(ref pointer); }
    }
    public Rule[] ReadOwned() {
      if (!CheckSublayer(false)) return new Rule[0];
      var rules = new List<Rule>(); uint total = 0;
      // A non-null enum template requires an actual layer GUID (zero is invalid).
      foreach (var requestedLayer in new[]{Layer, InboundLayer, BootLayer}) {
      IntPtr enumeration, template = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(EnumTemplate)));
      try {
        // Default enumeration hides boot/disabled filters: neither verification
        // nor cleanup may interpret an incomplete snapshot as an empty policy.
        Marshal.StructureToPtr(new EnumTemplate { Layer=requestedLayer, Flags=0x08 | 0x10, Actions=0xffffffff }, template, false);
        Check(FwpmFilterCreateEnumHandle0(handle, template, out enumeration));
      } finally { Marshal.FreeHGlobal(template); }
      try {
        while (true) {
          IntPtr entries = IntPtr.Zero; uint count;
          try {
            Check(FwpmFilterEnum0(handle, enumeration, 256, out entries, out count)); total += count;
            if (total > 100000) throw new InvalidOperationException("WFP enumeration limit");
            for (int i=0; i<count; i++) {
              var filter = Read<Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
              if (checkingPriority && filter.Sublayer != Policy.Sublayer && MayHardPermit(filter)) {
                IntPtr sublayer = IntPtr.Zero; Guid subkey=filter.Sublayer;
                try {
                  Check(FwpmSubLayerGetByKey0(handle, ref subkey, out sublayer));
                  if (HigherHardPermit(filter, Read<Sublayer>(sublayer).Weight, actualSublayerWeight)) throw new InvalidOperationException("IPv6 WFP priority conflict: " + filter.Display.Name + "; layer=" + filter.Layer + "; sublayer=" + filter.Sublayer + "; weight=" + Read<Sublayer>(sublayer).Weight + "; action=" + filter.Action.Type + "; conditions=" + filter.Count);
                } finally { if (sublayer != IntPtr.Zero) FwpmFreeMemory0(ref sublayer); }
              }
              if (filter.Sublayer != Policy.Sublayer) continue;
              bool boot=filter.Layer == BootLayer;
              // Boot filters are inactive after BFE's atomic transition to persistent filters.
              if ((filter.Layer != Layer && filter.Layer != InboundLayer && !boot) || !FilterFlagsValid(filter.Flags, boot) || filter.Provider != IntPtr.Zero || filter.ProviderData.Size != 0 || filter.Count > 3 ||
                  filter.Display.Name != Policy.Marker + "/" + filter.Key.ToString() || filter.Display.Description == null || !filter.Display.Description.StartsWith(Policy.Marker + "/") ||
                  filter.Weight.Type != 1 || filter.Weight.Byte != (filter.Action.Type == 0x1001 ? 0 : 15) || filter.Action.Key != Guid.Empty || filter.Context.Raw != 0) throw new InvalidOperationException("Unrecognized/disabled WFP filter; unchanged: " + filter.Display.Name + "; flags=" + filter.Flags + "; layer=" + filter.Layer + "; weightType=" + filter.Weight.Type + "; weightByte=" + filter.Weight.Byte + "; action=" + filter.Action.Type + "; actionKey=" + filter.Action.Key + "; context=" + filter.Context.Raw + "; conditions=" + filter.Count);
              var rule = new Rule { Id=filter.Key, Role=filter.Display.Description.Substring(Policy.Marker.Length + 1), Inbound=filter.Layer == InboundLayer, Boot=boot };
              if (filter.Action.Type != (rule.Block ? 0x1001u : 0x1002u)) throw new InvalidOperationException("WFP action mismatch");
              var seen = new HashSet<Guid>();
              for (int j=0; j<filter.Count; j++) {
                var c = Read<Condition>(IntPtr.Add(filter.Conditions, j * Marshal.SizeOf(typeof(Condition))));
                if (c.Match != 0 || !seen.Add(c.Key)) throw new InvalidOperationException("WFP condition mismatch");
                if (c.Key == RemoteKey && c.Value.Type == 257) { var bytes = Bytes(c.Value.Pointer, 17); rule.Remote = new IPAddress(bytes.Take(16).ToArray()).ToString() + "/" + bytes[16]; }
                else if ((c.Key == AppKey || c.Key == OriginalAppKey) && c.Value.Type == 12) { rule.AppId=ReadAppId(c.Value.Pointer); rule.OriginalApp=c.Key == OriginalAppKey; }
                else if (c.Key == InterfaceKey && c.Value.Type == 4) { rule.Luid=unchecked((ulong)Marshal.ReadInt64(c.Value.Pointer)).ToString(); }
                else throw new InvalidOperationException("Unknown WFP scope");
              }
              // Validate each recognized permit without requiring a complete set on cleanup.
              Policy.Validate(new[]{rule}, false);
              rules.Add(rule);
            }
            if (count < 256) break;
          } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
        }
      } finally { Check(FwpmFilterDestroyEnumHandle0(handle, enumeration)); }
      }
      return rules.ToArray();
    }
    public void Delete(Guid id) { Check(FwpmFilterDeleteByKey0(handle, ref id)); }
    public void Add(Rule rule) {
      var allocated = new List<IntPtr>();
      Func<byte[],IntPtr> buffer = bytes => { var p=Marshal.AllocHGlobal(bytes.Length); allocated.Add(p); Marshal.Copy(bytes,0,p,bytes.Length); return p; };
      Func<object,IntPtr> structure = value => { var p=Marshal.AllocHGlobal(Marshal.SizeOf(value)); allocated.Add(p); Marshal.StructureToPtr(value,p,false); return p; };
      try {
        var conditions = new List<Condition>();
        if (rule.Remote != "") { var parts=rule.Remote.Split('/'); var bytes=IPAddress.Parse(parts[0]).GetAddressBytes().Concat(new[]{Byte.Parse(parts[1])}).ToArray(); conditions.Add(new Condition{Key=RemoteKey,Value=new Value{Type=257,Pointer=buffer(bytes)}}); }
        if (rule.AppId != "") { var bytes=Enumerable.Range(0,rule.AppId.Length/2).Select(i => Convert.ToByte(rule.AppId.Substring(i*2,2),16)).ToArray(); var blob=new Blob{Size=(uint)bytes.Length,Data=buffer(bytes)}; conditions.Add(new Condition{Key=rule.OriginalApp ? OriginalAppKey : AppKey,Value=new Value{Type=12,Pointer=structure(blob)}}); }
        if (rule.Luid != "") conditions.Add(new Condition{Key=InterfaceKey,Value=new Value{Type=4,Pointer=buffer(BitConverter.GetBytes(UInt64.Parse(rule.Luid)))}});
        IntPtr array=IntPtr.Zero;
        if (conditions.Count > 0) { int size=Marshal.SizeOf(typeof(Condition)); array=Marshal.AllocHGlobal(size*conditions.Count); allocated.Add(array); for(int i=0;i<conditions.Count;i++) Marshal.StructureToPtr(conditions[i],IntPtr.Add(array,i*size),false); }
        var filter = new Filter { Key=rule.Id, Display=new Display{Name=Policy.Marker+"/"+rule.Id.ToString(),Description=Policy.Marker+"/"+rule.Role},
          Flags=rule.Boot ? 2u : 1u, Layer=rule.Boot ? BootLayer : (rule.Inbound ? InboundLayer : Layer), Sublayer=Policy.Sublayer, Weight=new Value{Type=1,Byte=(byte)(rule.Block ? 0 : 15)},
          Count=(uint)conditions.Count, Conditions=array, Action=new Action{Type=rule.Block ? 0x1001u : 0x1002u} };
        ulong id; Check(FwpmFilterAdd0(handle,ref filter,IntPtr.Zero,out id));
      } finally { foreach(var pointer in allocated) Marshal.FreeHGlobal(pointer); }
    }
  }
}
