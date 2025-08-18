# Patch for ZebraNativeUsbAdapter_64.dll (memory allocator workaround)

> [!NOTE]
> All the information contained within this repository is provided solely to help resolve compatibility issues with the original product.
> Zebra and ZXP are trademarks of Zebra Technologies Corporation. Authors of this repository are not affiliated with the original manufacturer or product.

## Crash

Zebra Link-OS Multiplatform SDK for Desktop Java - Card (Build: 2.12.3782 / 2.14.5198)
comes with the `ZebraNativeUsbAdapter_64.dll`, although there is an implementation
bug that would cause the SDK to crash with the following error when running
under 64 bit Java.

```
#
# A fatal error has been detected by the Java Runtime Environment:
#
#  EXCEPTION_ACCESS_VIOLATION (0xc0000005) at pc=0x00007ffedbdb25be, pid=11668, tid=0x0000000000002504
#
# JRE version: Java(TM) SE Runtime Environment (8.0_381) (build 1.8.0_381-b09)
# Java VM: Java HotSpot(TM) 64-Bit Server VM (25.381-b09 mixed mode windows-amd64 compressed oops)
# Problematic frame:
# C  [ZebraNativeUsbAdapter_64.dll+0x25be]
#
# Failed to write core dump. Minidumps are not enabled by default on client versions of Windows
#
# If you would like to submit a bug report, please visit:
#   http://bugreport.java.com/bugreport/crash.jsp
# The crash happened outside the Java Virtual Machine in native code.
# See problematic frame for where to report the bug.
#
```

## Patch

**Applying a patch:**
1. **Download [latest patch release](https://github.com/icedevml/zxp-native-usb-adapter-64bit-hack/releases)**
2. **Replace your original `ZebraNativeUsbAdapter_64.dll` with the two DLL files that are contained in the archive.**

That's it, now it should work under the recent versions of 64-bit Java JRE/JDK.

Kindly please star the project on GitHub to indicate that this patch works correctly, or please file an issue otherwise.

Release builds are built automatically by GitHub Actions Runner (hosted by GitHub).
Build provenance is available in [Actions / Attestation](https://github.com/icedevml/zxp-native-usb-adapter-64bit-hack/attestations).

## Test results 

| Result             | Patch version       | Java version                                      | OS version                                                        |
|--------------------|---------------------|---------------------------------------------------|-------------------------------------------------------------------|
| :white_check_mark: | build-20250817R04   | OpenJDK 64-Bit Server VM Zulu21.42+19-CA          | Windows 11 Pro 24H2 26100.4946 x64                                |
| :white_check_mark: | build-20250817R04   | OpenJDK 64-Bit Server VM Zulu21.42+19-CA          | Windows 10 Home 22H2 19045.3803 x64                               |
|                    | build-20250817R04   | OpenJDK 64-Bit Server VM Zulu21.42+19-CA          | Windows 7 x64                                                     |

---

## Technical details

Whenever Java SDK asks to open the connection with the printer, the original DLL would allocate
a heap object representing the printer connection and return a pointer back to Java SDK. However, there is
an implementation bug that would cause the DLL to cast the pointer to `int32_t` before returning it.
Similarly, the other DLL functions that allow subsequent interaction with the printer would also shrink
the pointer after receiving it as the argument.

The patch features a special proxy DLL called `MQALLOC.dll` that hooks and re-implements the C++ dynamic
allocator (`operator new` and `operator delete`). The additional DLL will ensure that heap objects are always
allocated on low virtual addresses (pointer values <= 2^31). Thus, the pointer values will
not get damaged, even if they would be inappropriately cast to `int32_t` anywhere.

The implementation of the allocator is extremely rudimental but sufficient for this particular case.
The entire original DLL would only allocate one type of objects, all with the same and known size.

Additionally, the original DLL is also slightly modified so the `Open()` call no longer leaks memory
when it fails to open the printer.

### Known bugs and limitations

* This patch's implementation will throw an exception once there are more than 1024 open printer handles
  at once (this shouldn't ever happen in practice, unless there is a bug somewhere else).

### Debugging

Set `DEBUG_MQALLOC=1` environment variable and launch Java with your application.
Debug printouts from the allocator will be written on standard error stream.

### Bug checks

The patch contains series of sanity checks, in case when anything odd will be detected, the message starting with `[MQALLOC] BUG!`
will be logged on the standard error stream and the entire JRE will be torn down with an exception.

### Building locally

Only if you want to build this patch from scratch:

1. Get the original `ZebraNativeUsbAdapter_64.dll` from [the SDK](https://www.zebra.com/gb/en/support-downloads/software/printer-software/card-sdk.html?downloadId=8b36dbcf-976f-444e-b484-36225ea97ad6) (SHA256: `034bd1293128507120005ebb6a5ba510b614932292e648e15a77677c09c63f1e`).
2. Execute the following command to patch the original DLL (this command doesn't need to be run inside git repository):
   ```
   # ensure that the diff file doesn't have CRLF
   dos2unix ZebraNativeUsbAdapter_64.diff
   # apply the patch to the binary file
   git apply < ZebraNativeUsbAdapter_64.diff
   ```
3. Build the source code from this repository with CMake (using MSVC, in "Release" profile), this would generate `MQALLOC.dll`.
4. Put the patched `ZebraNativeUsbAdapter_64.dll` that you've got from step (2) together with `MQALLOC.dll` instead of the original DLL. Both files should be placed in the same directory.
