


// SNKT_wifi_help code for hide Agent process
// URL： www.simplenktools.cn
// code by ┏姠咗赱ペ

#include <windows.h>




#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,              // 0        Y        N
	SystemProcessorInformation,          // 1        Y        N
	SystemPerformanceInformation,        // 2        Y        N
	SystemTimeOfDayInformation,          // 3        Y        N
	SystemNotImplemented1,               // 4        Y        N
	SystemProcessesAndThreadsInformation, // 5       Y        N
	SystemCallCounts,                    // 6        Y        N
	SystemConfigurationInformation,      // 7        Y        N
	SystemProcessorTimes,                // 8        Y        N
	SystemGlobalFlag,                    // 9        Y        Y
	SystemNotImplemented2,               // 10       Y        N
	SystemModuleInformation,             // 11       Y        N
	SystemLockInformation,               // 12       Y        N
	SystemNotImplemented3,               // 13       Y        N
	SystemNotImplemented4,               // 14       Y        N
	SystemNotImplemented5,               // 15       Y        N
	SystemHandleInformation,             // 16       Y        N
	SystemObjectInformation,             // 17       Y        N
	SystemPagefileInformation,           // 18       Y        N
	SystemInstructionEmulationCounts,    // 19       Y        N
	SystemInvalidInfoClass1,             // 20
	SystemCacheInformation,              // 21       Y        Y
	SystemPoolTagInformation,            // 22       Y        N
	SystemProcessorStatistics,           // 23       Y        N
	SystemDpcInformation,                // 24       Y        Y
	SystemNotImplemented6,               // 25       Y        N
	SystemLoadImage,                     // 26       N        Y
	SystemUnloadImage,                   // 27       N        Y
	SystemTimeAdjustment,                // 28       Y        Y
	SystemNotImplemented7,               // 29       Y        N
	SystemNotImplemented8,               // 30       Y        N
	SystemNotImplemented9,               // 31       Y        N
	SystemCrashDumpInformation,          // 32       Y        N
	SystemExceptionInformation,          // 33       Y        N
	SystemCrashDumpStateInformation,     // 34       Y        Y/N
	SystemKernelDebuggerInformation,     // 35       Y        N
	SystemContextSwitchInformation,      // 36       Y        N
	SystemRegistryQuotaInformation,      // 37       Y        Y
	SystemLoadAndCallImage,              // 38       N        Y
	SystemPrioritySeparation,            // 39       N        Y
	SystemNotImplemented10,              // 40       Y        N
	SystemNotImplemented11,              // 41       Y        N
	SystemInvalidInfoClass2,             // 42
	SystemInvalidInfoClass3,             // 43
	SystemTimeZoneInformation,           // 44       Y        N
	SystemLookasideInformation,          // 45       Y        N
	SystemSetTimeSlipEvent,              // 46       N        Y
	SystemCreateSession,                 // 47       N        Y
	SystemDeleteSession,                 // 48       N        Y
	SystemInvalidInfoClass4,             // 49
	SystemRangeStartInformation,         // 50       Y        N
	SystemVerifierInformation,           // 51       Y        Y
	SystemAddVerifier,                   // 52       N        Y
	SystemSessionProcessesInformation    // 53       Y        N
} SYSTEM_INFORMATION_CLASS;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID,*PCLIENT_ID;

typedef struct
{
	USHORT Length;
	USHORT MaxLen;
	USHORT *Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES 
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES; 

typedef struct _IO_COUNTERSEX {
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} IO_COUNTERSEX, *PIO_COUNTERSEX;

typedef enum {
    StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _SYSTEM_THREADS {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    ULONG Priority;
    ULONG BasePriority;
    ULONG ContextSwitchCount;
    THREAD_STATE State;
    ULONG WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES { 
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    ULONG BasePriority;
    ULONG ProcessId;
    ULONG InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    VM_COUNTERS VmCounters;
    IO_COUNTERSEX IoCounters;  
    SYSTEM_THREADS Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;


typedef NTSTATUS (NTAPI *ZWQUERYSYSTEMINFORMATION)(
								  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
								  OUT PVOID SystemInformation,
								  IN ULONG SystemInformationLength,
								  OUT PULONG ReturnLength OPTIONAL
								  );
//APIHOOK结构   
#define  CodeLength 7
typedef struct   
{ 
	FARPROC NewFuncAddr;
	FARPROC OldFuncAddr;
	BYTE    OldCode[CodeLength];   
	BYTE    NewCode[CodeLength]; 
} HOOKSTRUCT;   




BYTE hook_code[7] =   {0xb8, 0, 0, 0, 0 ,0xff, 0xe0};//构造 jmp code
ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;	 
HANDLE hProcess=0;
HOOKSTRUCT hookinfo;
																					
								
int HidePid = 0;				//待隐藏的进程PID  提供 360wifi.exe 360AP.exe 等wifi代理软件的进程ID 以保证客户端跳过其检索

BOOL WINAPI inlinehook(HOOKSTRUCT *hookfunc);
BOOL WINAPI uninlinehook(HOOKSTRUCT *hookfunc);
void WINAPI init(int *pid); 


NTSTATUS NTAPI MyZwQuerySystemInformation(
						   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
						   OUT PVOID SystemInformation,
						   IN ULONG SystemInformationLength,
						   OUT PULONG ReturnLength OPTIONAL
							 );


void init(int pid)
{


	HidePid = pid;
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(LoadLibraryA("ntdll.dll"), "ZwQuerySystemInformation");
	memset(hookinfo.NewCode,0,CodeLength);
	memset(hookinfo.OldCode,0,CodeLength);
	memcpy(hookinfo.NewCode,hook_code,CodeLength);
	hookinfo.NewFuncAddr=(FARPROC)MyZwQuerySystemInformation;
	hookinfo.OldFuncAddr=(FARPROC)ZwQuerySystemInformation;
	*((ULONG*)(hookinfo.NewCode+1))=(ULONG)MyZwQuerySystemInformation;
	inlinehook(&hookinfo);
}

NTSTATUS NTAPI MyZwQuerySystemInformation(
								 IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
								 OUT PVOID SystemInformation,
								 IN ULONG SystemInformationLength,
								 OUT PULONG ReturnLength OPTIONAL
								 )
{
	NTSTATUS ntStatus;
	PSYSTEM_PROCESSES SystemProcessesinfo=NULL,Prev;
	uninlinehook(&hookinfo);
	ntStatus=((ZWQUERYSYSTEMINFORMATION)ZwQuerySystemInformation)(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);
	if (NT_SUCCESS(ntStatus) && SystemInformationClass==SystemProcessesAndThreadsInformation)
	{
		SystemProcessesinfo = (PSYSTEM_PROCESSES)SystemInformation;
		
		while (TRUE)
		{	
			
			if (SystemProcessesinfo->ProcessId == HidePid) //需要隐藏的PID 
			{
				if (SystemProcessesinfo->NextEntryDelta)
				{
					//需要隐藏的进程后面还有进程时直接指向下一个链表指针

					DWORD dwOldProtect;
					//改成读写可执行状态
					if(!VirtualProtect((void *)Prev, sizeof(_SYSTEM_PROCESSES)*3, PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						//MessageBox(NULL,"VirtualProtect error!","error",MB_OK);
						return false;
					}
					Prev->NextEntryDelta += SystemProcessesinfo->NextEntryDelta;
					VirtualProtect((void *)Prev, sizeof(_SYSTEM_PROCESSES)*3, dwOldProtect, 0);
				}
				else
				{
					//进程处于最后一个数据把上一个链表指针的置0
					
					Prev->NextEntryDelta=0;
				}
				break;
			}
			if (!SystemProcessesinfo->NextEntryDelta) break;
			Prev=SystemProcessesinfo;
			SystemProcessesinfo = (PSYSTEM_PROCESSES)((char *)SystemProcessesinfo + SystemProcessesinfo->NextEntryDelta);
		}
	}
	inlinehook(&hookinfo);
	return ntStatus;
}

BOOL WINAPI inlinehook(HOOKSTRUCT *hookfunc)
{
	
	DWORD dwOldProtect;
	//改成读写可执行状态
	if(!VirtualProtect((void *)hookfunc->OldFuncAddr, CodeLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		//(NULL,"VirtualProtect error!","error",MB_OK);
		return false;
	}
	//保存原机器码
	memcpy(hookfunc->OldCode,(unsigned char *)hookfunc->OldFuncAddr,CodeLength);
	if(memcpy((unsigned char *)hookfunc->OldFuncAddr, hookfunc->NewCode, CodeLength)==0)
	{
		//(NULL,"write error!","error",MB_OK);
		return false;
	}
	VirtualProtect((void *)hookfunc->OldFuncAddr, CodeLength, dwOldProtect, 0);

	return true;
}
BOOL WINAPI uninlinehook(HOOKSTRUCT *hookfunc)
{
	
	DWORD dwOldProtect;
	if(!VirtualProtect((void *)hookfunc->OldFuncAddr, CodeLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		//(NULL,"VirtualProtect error!","error",MB_OK);
		return false;
	}
	//改回原机器码
	if(memcpy((unsigned char *)hookfunc->OldFuncAddr, hookfunc->OldCode, CodeLength)==0)
	{
		
		//(NULL,"write error!","error",MB_OK);
		return false;
	}
	VirtualProtect((void *)hookfunc->OldFuncAddr, CodeLength, dwOldProtect, 0);

	return true;
}

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		init(GetCurrentProcessId());//获得当前自己进程ID 用于测试效果
		break;
	case DLL_PROCESS_DETACH:
		uninlinehook(&hookinfo);
		break;
	}
    return TRUE;
}

