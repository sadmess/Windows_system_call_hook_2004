# Syscall Hook for windows-2004

you can change the hooksyscall by change those code easily.and the syscall name should delete the "Nt".

```
KhSetResetHook:
	if (!NT_SUCCESS(KeSetSystemServiceCallback("DisplayString", TRUE, (ULONG64)callback, NULL)))
	{
		ntstatus = STATUS_UNSUCCESSFUL;
		goto exit;
	}

```

# Use

you should build it with vs2019(wdk10) and use kdmapper (or any other way) to load the driver.

*if you donnot close patchguard, you will get bsod*

This hook way still not be found by EAC BE etc.

Have good cheat day!
