using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

internal static class WindowsServiceTools {
  const uint ScManagerConnect=0x0001,ServiceChangeConfig=0x0002,ServiceDelete=0x00010000,NoChange=0xFFFFFFFF;
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ChangeServiceConfig(IntPtr service,uint serviceType,uint startType,uint errorControl,string binaryPath,string loadOrderGroup,IntPtr tag,string dependencies,string account,string password,string displayName);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool DeleteService(IntPtr service);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);

  internal static void SetStartType(string name,uint startType){
    IntPtr manager=OpenSCManager(null,null,ScManagerConnect);if(manager==IntPtr.Zero)throw new Win32Exception();
    IntPtr service=IntPtr.Zero;
    try{service=OpenService(manager,name,ServiceChangeConfig);if(service==IntPtr.Zero)throw new Win32Exception();if(!ChangeServiceConfig(service,NoChange,startType,NoChange,null,null,IntPtr.Zero,null,null,null,null))throw new Win32Exception();}
    finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
  }
  internal static void Remove(string name){
    IntPtr manager=OpenSCManager(null,null,ScManagerConnect);if(manager==IntPtr.Zero)throw new Win32Exception();
    IntPtr service=IntPtr.Zero;
    try{service=OpenService(manager,name,ServiceDelete);if(service==IntPtr.Zero){if(Marshal.GetLastWin32Error()==1060)return;throw new Win32Exception();}if(!DeleteService(service)){var error=Marshal.GetLastWin32Error();if(error!=1072)throw new Win32Exception(error);}}
    finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
  }
}
