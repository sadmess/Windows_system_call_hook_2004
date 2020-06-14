# Syscall Hook for windows-2004

you can change the hooksyscall by change those code easily.and the syscall name should delete the "Nt"

```
KhSetResetHook:
	if (!NT_SUCCESS(KeSetSystemServiceCallback("DisplayString", TRUE, (ULONG64)callback, NULL)))
	{
		ntstatus = STATUS_UNSUCCESSFUL;
		goto exit;
	}

```
