#include <Windows.h>
#include <psapi.h>          // Para EnumDeviceDrivers, GetDeviceDriverBaseName e GetDeviceDriverFileName
#include <tchar.h>          // Para o tipo TCHAR usado em GetDeviceDriverBaseName e GetDeviceDriverFileName
#include <strsafe.h>        // Para funções seguras de manipulação de strings, caso queira usá-las
#include <shellapi.h>       // Para SHELL_EXECUTE_INFO, caso seja usado em outras partes para manipulação do Windows
#include <SetupAPI.h>
#include <intrin.h>
#include <stdlib.h>         // Para malloc e free
#include <string.h>         // Para strtok e strstr
#include <vector>           // Para o uso de std::vector em várias funções
#include <iostream>         // Para debugging ou saídas de console (opcional)

#include "../Utils/xorstr.h"
#include "../Authentication/Authentication.h"
#include "Services.h"
#include <cfgmgr32.h>

#pragma comment(lib, "setupapi.lib")


extern "C" NTSTATUS NTAPI RtlGetVersion( RTL_OSVERSIONINFOW * lpVersionInformation ); //used in GetWindowsVersion

bool Services::GetServiceModules( )
{
	SC_HANDLE scmHandle = NULL , serviceHandle = NULL;
	DWORD bytesNeeded , servicesReturned , resumeHandle = 0;
	ENUM_SERVICE_STATUS_PROCESS * services;
	BOOL result;

	scmHandle = OpenSCManager( NULL , NULL , SC_MANAGER_ENUMERATE_SERVICE );

	if ( scmHandle == NULL )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to open Service Control Manager @ GetServiceModules: %lu\n" , GetLastError( ) );
		return FALSE;
	}

	result = EnumServicesStatusEx( scmHandle , SC_ENUM_PROCESS_INFO , SERVICE_WIN32 , SERVICE_STATE_ALL , NULL , 0 , &bytesNeeded , &servicesReturned , &resumeHandle , NULL );

	if ( !result && GetLastError( ) != ERROR_MORE_DATA )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to enumerate services @ GetServiceModules: %lu\n" , GetLastError( ) );
		CloseServiceHandle( scmHandle );
		return FALSE;
	}

	services = ( ENUM_SERVICE_STATUS_PROCESS * ) malloc( bytesNeeded );

	if ( services == NULL )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Memory allocation failed @ GetServiceModules" );
		CloseServiceHandle( scmHandle );
		return FALSE;
	}

	result = EnumServicesStatusEx( scmHandle , SC_ENUM_PROCESS_INFO , SERVICE_WIN32 , SERVICE_STATE_ALL , ( LPBYTE ) services , bytesNeeded , &bytesNeeded , &servicesReturned , &resumeHandle , NULL );

	if ( !result )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to enumerate services @ GetServiceModules: %lu\n" , GetLastError( ) );
		free( services );
		CloseServiceHandle( scmHandle );
		return FALSE;
	}

	for ( DWORD i = 0; i < servicesReturned; i++ )  //iterate services and add to our managed list
	{
		Service * service = new Service( );
		service->pid = services[ i ].ServiceStatusProcess.dwProcessId;
		service->displayName = services[ i ].lpDisplayName;
		service->serviceName = services[ i ].lpServiceName;

		switch ( services[ i ].ServiceStatusProcess.dwCurrentState )
		{
		case SERVICE_STOPPED:
			service->isRunning = false;
			break;
		case SERVICE_RUNNING:
			service->isRunning = true;
			break;
		case SERVICE_PAUSED:
			service->isRunning = false;
			break;
		default:
			break;
		}

		ServiceList.push_back( service );
	}

	free( services );
	CloseServiceHandle( scmHandle );

	return TRUE;
}

/*
	GetLoadedDrivers - Fills the `DriverPaths` class member variable with a list of drivers loaded on the system
	returns TRUE if the function succeeded
*/
bool Services::GetLoadedDrivers( std::vector<std::string> * buffer )
{
	DWORD cbNeeded;
	HMODULE drivers[ 1024 ];
	DWORD numDrivers;

	if ( !EnumDeviceDrivers( ( LPVOID * ) drivers , sizeof( drivers ) , &cbNeeded ) )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to enumerate device drivers @ GetLoadedDrivers" );
		return FALSE;
	}

	numDrivers = cbNeeded / sizeof( HMODULE );

	for ( DWORD i = 0; i < numDrivers; i++ )
	{
		TCHAR driverName[ MAX_PATH ];
		TCHAR driverPath[ MAX_PATH ];

		if ( GetDeviceDriverBaseName( drivers[ i ] , driverName , MAX_PATH ) && GetDeviceDriverFileName( drivers[ i ] , driverPath , MAX_PATH ) )
		{
			buffer->push_back( driverPath );
		}
		else
		{
			//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to get driver information @ GetLoadedDrivers : error %d\n" , GetLastError( ) );
			return FALSE;
		}
	}

	return TRUE;
}

/*
	GetUnsignedDrivers - returns a list of unsigned driver names loaded on the machine
*/
std::vector<std::string> Services::GetUnsignedDrivers( )
{
	std::vector<std::string> unsignedDrivers;

	if ( DriverPaths.size( ) == 0 )
	{
		if ( !GetLoadedDrivers( &DriverPaths ) )
		{
			//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to get driver list @ GetUnsignedDrivers : error %d\n" , GetLastError( ) );
			return unsignedDrivers;
		}
	}

	for ( const std::string & driverPath : DriverPaths )
	{
		if ( !Authentication::Get( ).HasSignature( driverPath.c_str( ) ) )
		{
			//Logger::::logfw(xorstr_( "UltimateAnticheat.log" , Warning , L"Found unsigned or outdated certificate on driver: %s\n" , driverPath.c_str( ) );
			unsignedDrivers.push_back( driverPath );
		}
		else
		{
			//Logger::::logfw(xorstr_( "UltimateAnticheat.log" , Info , L"Driver is signed: %s\n" , driverPath.c_str( ) );
		}
	}

	return unsignedDrivers;
}

/*
	IsMachineAllowingSelfSignedDrivers - Opens BCDEdit.exe and pipes output to check if testsigning is enabled. May require running program as administrator.
	returns TRUE if test signing mode was found.
*/
bool Services::IsTestsigningEnabled( )
{
	HANDLE hReadPipe , hWritePipe;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char szOutput[ 1024 ];
	DWORD bytesRead;
	BOOL foundTestsigning = FALSE;

	sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	std::string volumeName = GetWindowsDrive( );

	if ( !CreatePipe( &hReadPipe , &hWritePipe , &sa , 0 ) ) //use a pipe to read output of bcdedit command
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "CreatePipe failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n" , GetLastError( ) );
		return foundTestsigning;
	}

	memset( &si , 0 , sizeof( si ) );
	si.cb = sizeof( si );
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;

	std::string bcdedit_location = xorstr_( "Windows\\System32\\bcdedit.exe" );
	std::string fullpath_bcdedit = ( volumeName.c_str( ) + bcdedit_location );

	if ( !CreateProcessA( fullpath_bcdedit.c_str( ) , NULL , NULL , NULL , TRUE , CREATE_NO_WINDOW , NULL , NULL , &si , &pi ) )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "CreateProcess failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n" , GetLastError( ) );
		CloseHandle( hReadPipe );
		CloseHandle( hWritePipe );
		return FALSE;
	}

	//..wait for the process to finish
	WaitForSingleObject( pi.hProcess , INFINITE );

	CloseHandle( hWritePipe );
	CloseHandle( pi.hThread );

	if ( !ReadFile( hReadPipe , szOutput , 1024 - 1 , &bytesRead , NULL ) ) //now read our pipe
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "ReadFile failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n" , GetLastError( ) );
		CloseHandle( hReadPipe );
		return FALSE;
	}

	CloseHandle( hReadPipe );

	szOutput[ bytesRead ] = '\0';

	if ( strstr( szOutput , xorstr_( "The boot configuration data store could not be opened" ) ) != NULL )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers. Please make sure program is run as administrator\n" );
		foundTestsigning = FALSE;
	}

	char * token = strtok( szOutput , xorstr_( "\r\n" ) );

	while ( token != NULL )      //Iterate through tokens
	{
		if ( strstr( token , xorstr_( "testsigning" ) ) != NULL && strstr( token , xorstr_( "Yes" ) ) != NULL )
		{
			foundTestsigning = TRUE;
		}

		token = strtok( NULL , xorstr_( "\r\n" ) );
	}

	return foundTestsigning;
}


/*
	IsDebugModeEnabled - Opens BCDEdit.exe and pipes output to check if debug mode is enabled. May require running program as administrator.
	returns TRUE if debug  mode is enabled.
*/
bool Services::IsDebugModeEnabled( )
{
	HANDLE hReadPipe , hWritePipe;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char szOutput[ 1024 ];
	DWORD bytesRead;
	BOOL foundKDebugMode = FALSE;

	sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	std::string volumeName = GetWindowsDrive( );

	if ( !CreatePipe( &hReadPipe , &hWritePipe , &sa , 0 ) ) //use a pipe to read output of bcdedit command
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "CreatePipe failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n" , GetLastError( ) );
		return foundKDebugMode;
	}

	memset( &si , 0 , sizeof( si ) );
	si.cb = sizeof( si );
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;

	std::string bcdedit_location = xorstr_( "Windows\\System32\\bcdedit.exe" );
	std::string fullpath_bcdedit = ( volumeName + bcdedit_location );

	if ( !CreateProcessA( fullpath_bcdedit.c_str( ) , NULL , NULL , NULL , TRUE , CREATE_NO_WINDOW , NULL , NULL , &si , &pi ) )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "CreateProcess failed @ Services::IsDebugModeEnabled: %d\n" , GetLastError( ) );
		CloseHandle( hReadPipe );
		CloseHandle( hWritePipe );
		return foundKDebugMode;
	}

	//..wait for the process to finish
	WaitForSingleObject( pi.hProcess , INFINITE );

	CloseHandle( hWritePipe );
	CloseHandle( pi.hThread );

	if ( !ReadFile( hReadPipe , szOutput , 1024 - 1 , &bytesRead , NULL ) ) //now read our pipe
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "ReadFile failed @ Services::IsDebugModeEnabled: %d\n" , GetLastError( ) );
		CloseHandle( hReadPipe );
		return foundKDebugMode;
	}

	CloseHandle( hReadPipe );

	szOutput[ bytesRead ] = '\0';

	if ( strstr( szOutput , xorstr_( "The boot configuration data store could not be opened" ) ) != NULL )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers. Please make sure program is run as administrator\n" );
		foundKDebugMode = FALSE;
	}

	char * token = strtok( szOutput , xorstr_( "\r\n" ) ); //split based on new line

	while ( token != NULL )      //Iterate through tokens, bothxorstr_( "yes" andxorstr_( "debug" on same line = debug mode
	{
		if ( strstr( token , xorstr_( "debug" ) ) != NULL && strstr( token , xorstr_( "Yes" ) ) != NULL )
		{
			foundKDebugMode = TRUE;
		}

		token = strtok( NULL , xorstr_( "\r\n" ) );
	}

	return foundKDebugMode;
}

/*
	IsSecureBootEnabled - checks if secure bool is enabled on machine
*/
bool Services::IsSecureBootEnabled( )
{
	HANDLE hReadPipe , hWritePipe;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char szOutput[ 1024 ];
	DWORD bytesRead;
	BOOL secureBootEnabled = FALSE;

	sa.nLength = sizeof( SECURITY_ATTRIBUTES );
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	if ( !CreatePipe( &hReadPipe , &hWritePipe , &sa , 0 ) ) //use a pipe to read output of bcdedit command
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "CreatePipe failed @ Services::IsSecureBootEnabled: %d\n" , GetLastError( ) );
		return FALSE;
	}

	memset( &si , 0 , sizeof( si ) );
	si.cb = sizeof( si );
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;

	if ( !CreateProcessA( NULL , ( LPSTR ) xorstr_( "powershell -c \"Confirm-SecureBootUEFI\"" ) , NULL , NULL , TRUE , CREATE_NO_WINDOW , NULL , NULL , &si , &pi ) )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "CreateProcess failed @ Services::IsSecureBootEnabled: %d\n" , GetLastError( ) );
		CloseHandle( hReadPipe );
		CloseHandle( hWritePipe );
		return FALSE;
	}

	//..wait for the process to finish
	WaitForSingleObject( pi.hProcess , INFINITE );

	CloseHandle( hWritePipe );
	CloseHandle( pi.hThread );

	if ( !ReadFile( hReadPipe , szOutput , 1024 - 1 , &bytesRead , NULL ) ) //now read our pipe
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "ReadFile failed @ Services::IsSecureBootEnabled: %d\n" , GetLastError( ) );
		CloseHandle( hReadPipe );
		return FALSE;
	}

	CloseHandle( hReadPipe );

	szOutput[ bytesRead ] = '\0';

	if ( strstr( szOutput , xorstr_( "Cmdlet not supported on this platform" ) ) != NULL ) //
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers. Please make sure program is run as administrator\n" );
		secureBootEnabled = FALSE;
	}

	if ( strstr( szOutput , xorstr_( "False" ) ) != NULL )
	{
		secureBootEnabled = FALSE;
	}
	else if ( strcmp( szOutput , xorstr_( "True" ) ) != NULL )
	{
		secureBootEnabled = TRUE;
	}

	return secureBootEnabled;
}

/*
	GetWindowsDrive - return drive where windows is installed, such as C:\\
*/
std::string Services::GetWindowsDrive( )
{
	CHAR volumePath[ MAX_PATH ];
	DWORD charCount;

	charCount = GetWindowsDirectoryA( volumePath , MAX_PATH );
	if ( charCount == 0 )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to retrieve Windows directory path @ Services::GetWindowsPath: %d\n" , GetLastError( ) );
		return xorstr_( "" );
	}

	CHAR volumeName[ MAX_PATH ];
	if ( !GetVolumePathNameA( volumePath , volumeName , MAX_PATH ) )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to retrieve volume path name @ Services::GetWindowsPath: %d\n" , GetLastError( ) );
		return xorstr_( "" );
	}

	return volumeName;
}

/*
	GetWindowsDriveW - return drive where windows is installed, such as C:\\
*/
std::string Services::GetWindowsDriveW( )
{
	char volumePath[ MAX_PATH ];
	DWORD charCount;

	charCount = GetWindowsDirectory( volumePath , MAX_PATH );
	if ( charCount == 0 )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to retrieve Windows directory path @ Services::GetWindowsPathW: %d\n" , GetLastError( ) );
		return xorstr_( "" );
	}

	char volumeName[ MAX_PATH ];
	if ( !GetVolumePathName( volumePath , volumeName , MAX_PATH ) )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Err ,xorstr_( "Failed to retrieve volume path name @ Services::GetWindowsPathW: %d\n" , GetLastError( ) );
		return xorstr_( "" );
	}

	return volumeName;
}

/*
	IsRunningAsAdmin - returns TRUE if the application is running as administrator context
*/
bool Services::IsRunningAsAdmin( )
{
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if ( AllocateAndInitializeSid( &NtAuthority , 2 , SECURITY_BUILTIN_DOMAIN_RID , DOMAIN_ALIAS_RID_ADMINS , 0 , 0 , 0 , 0 , 0 , 0 , &adminGroup ) )
	{
		CheckTokenMembership( NULL , adminGroup , &isAdmin );
		FreeSid( adminGroup );
	}
	return isAdmin;
}

/*
	GetHardwareDevicesW - returns a list<DeviceW>  representing various devices on the machine
*/
std::vector<DeviceW> Services::GetHardwareDevicesW( )
{
	std::vector<DeviceW> deviceList;

	HDEVINFO deviceInfoSet;
	SP_DEVINFO_DATA deviceInfoData;
	DWORD deviceIndex = 0;

	deviceInfoSet = SetupDiGetClassDevsA( NULL , xorstr_( "PCI" ) , NULL , DIGCF_PRESENT | DIGCF_ALLCLASSES );     //Get the list of all PCI devices

	if ( deviceInfoSet == INVALID_HANDLE_VALUE )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Warning ,xorstr_( "SetupDiGetClassDevs failed with error: %d @ Services::GetHardwareDevicesW\n" , GetLastError( ) );
		return {};
	}

	deviceInfoData.cbSize = sizeof( SP_DEVINFO_DATA );

	while ( SetupDiEnumDeviceInfo( deviceInfoSet , deviceIndex , &deviceInfoData ) )
	{
		deviceIndex++;
		DeviceW d;

		TCHAR deviceInstanceId[ MAX_DEVICE_ID_LEN ];
		if ( CM_Get_Device_ID( deviceInfoData.DevInst , deviceInstanceId , MAX_DEVICE_ID_LEN , 0 ) == CR_SUCCESS )         // Get the device instance ID
		{
			d.InstanceID = std::string( deviceInstanceId );
		}
		else
		{
			continue;
		}

		TCHAR deviceDescription[ 1024 ];
		if ( SetupDiGetDeviceRegistryProperty( deviceInfoSet , &deviceInfoData , SPDRP_DEVICEDESC , NULL , ( PBYTE ) deviceDescription , sizeof( deviceDescription ) , NULL ) )          // Get the device description
		{
			d.Description = std::string( deviceDescription );
		}
		else
		{
			continue;
		}

		deviceList.push_back( d );
	}

	if ( GetLastError( ) != ERROR_NO_MORE_ITEMS )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Warning ,xorstr_( "SetupDiEnumDeviceInfo failed with error: %d @ Services::GetHardwareDevicesW\n" , GetLastError( ) );
	}

	SetupDiDestroyDeviceInfoList( deviceInfoSet );

	return deviceList;
}

bool Services::IsSecureBootEnabled_RegKey( )
{
	HKEY hKey;
	LONG lResult;
	DWORD dwSize = sizeof( DWORD );
	DWORD dwValue = 0;
	const char * registryPath = xorstr_( "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State" ); //optionally xor this
	const char * valueName = xorstr_( "UEFISecureBootEnabled" );

	lResult = RegOpenKeyExA( HKEY_LOCAL_MACHINE , registryPath , 0 , KEY_READ , &hKey );

	if ( lResult != ERROR_SUCCESS )
	{
		return FALSE;
	}

	lResult = RegQueryValueExA( hKey , valueName , NULL , NULL , ( LPBYTE ) &dwValue , &dwSize );

	if ( lResult != ERROR_SUCCESS )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Warning ,xorstr_( "RegCloseKey failed with error: %d @ Services::IsSecureBootEnabled_RegKey\n" , lResult );
		RegCloseKey( hKey );
		return FALSE;
	}

	if ( dwValue == 1 )
	{
		RegCloseKey( hKey );
		return TRUE;
	}
	else
	{
		RegCloseKey( hKey );
		return FALSE;
	}
}

/*
	   CheckUSBDevices - returns TRUE if any hardware in the PCIe slot are blacklisted (DMA involved)
*/
bool Services::CheckUSBDevices( )
{
	HDEVINFO deviceInfoSet;
	SP_DEVINFO_DATA deviceInfoData;
	DWORD i;
	TCHAR deviceID[ MAX_PATH ];

	BOOL foundFTDI = FALSE;
	BOOL foundLeonardo = FALSE;

	deviceInfoSet = SetupDiGetClassDevs( NULL , TEXT( xorstr_( "USB" ) ) , NULL , DIGCF_PRESENT | DIGCF_ALLCLASSES );

	if ( deviceInfoSet == INVALID_HANDLE_VALUE )
	{
		//std::cerr <<xorstr_( "Failed to get device information set." << std::endl;
		return FALSE;
	}

	deviceInfoData.cbSize = sizeof( SP_DEVINFO_DATA );

	for ( i = 0; SetupDiEnumDeviceInfo( deviceInfoSet , i , &deviceInfoData ); i++ )
	{
		if ( SetupDiGetDeviceRegistryProperty( deviceInfoSet , &deviceInfoData , SPDRP_HARDWAREID , NULL , ( PBYTE ) deviceID , sizeof( deviceID ) , NULL ) )
		{
			if ( _tcsstr( deviceID , TEXT( xorstr_( "VID_0403" ) ) ) && _tcsstr( deviceID , TEXT( xorstr_( "PID_6010" ) ) ) )  //Check for FTDI FT601 in the device ID
			{
				foundFTDI = TRUE;
			}

			if ( _tcsstr( deviceID , TEXT( xorstr_( "VID_0403" ) ) ) && _tcsstr( deviceID , TEXT( xorstr_( "PID_6000" ) ) ) )  //Check for FTDI FT600 in the device ID
			{
				foundFTDI = TRUE;
			}

			if ( _tcsstr( deviceID , TEXT( xorstr_( "VID_2341" ) ) ) && _tcsstr( deviceID , TEXT( xorstr_( "PID_8036" ) ) ) )  //Check for Arduino Leonardo
			{
				foundLeonardo = TRUE;
			}
		}
	}

	SetupDiDestroyDeviceInfoList( deviceInfoSet );

	return ( foundFTDI | foundLeonardo );
}

/*
	WindowsVersions GetWindowsVersion() - returns current machine version
*/
WindowsVersion Services::GetWindowsVersion( )
{
	RTL_OSVERSIONINFOW osVersionInfo;
	osVersionInfo.dwOSVersionInfoSize = sizeof( osVersionInfo );

	NTSTATUS status = RtlGetVersion( &osVersionInfo );

	if ( status != 0 )
	{
		//Logger::::logf(xorstr_( "UltimateAnticheat.log" , Warning ,xorstr_( "Services::GetWindowsMajorVersion failed with error: %x" , status );
		return ErrorUnknown;
	}

	if ( osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 0 )
	{
		return Windows2000;
	}
	else if ( osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 1 )
	{
		return WindowsXP;
	}
	else if ( osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 2 )
	{
		return WindowsXPProfessionalx64;
	}
	else if ( osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 0 )
	{
		return WindowsVista;
	}
	else if ( osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 1 )
	{
		return Windows7;
	}
	else if ( osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 2 )
	{
		return Windows8;
	}
	else if ( osVersionInfo.dwMajorVersion == 10 && osVersionInfo.dwMinorVersion == 0 )
	{
		if ( osVersionInfo.dwBuildNumber < 22000 )
		{
			return Windows10;
		}
		else
		{
			return Windows11;
		}
	}

	return ErrorUnknown;
}

/*
	Services::IsHypervisor - returns true if a hypervisor is detected by using the __cpuid intrinsic function
	the 31st bit of ECX indicates a hypervisor
*/
bool Services::IsHypervisor( )
{
	int cpuInfo[ 4 ] = { 0 };
	__cpuid( cpuInfo , 1 );
	return ( cpuInfo[ 2 ] & ( 1 << 31 ) ) != 0;     // bit 31 of ECX = 1 means a hypervisor is present
}

/*
	Services::GetHypervisorVendor - fetches the hypervisor vendor as `vendor`
Additionally, 0x40000001 to 0x400000FF can be queries in the 2nd parameter to __cpuid for more hypervisor-specific info
*/
void Services::GetHypervisorVendor( __out char vendor[ 13 ] )
{
	int cpuInfo[ 4 ] = { 0 };

	__cpuid( cpuInfo , 0x40000000 ); //2nd param is passed to EAX

	// Copy vendor ID from EBX, ECX, EDX to vendor string
	( ( int * ) vendor )[ 0 ] = cpuInfo[ 1 ];  //BX
	( ( int * ) vendor )[ 1 ] = cpuInfo[ 2 ];  //CX
	( ( int * ) vendor )[ 2 ] = cpuInfo[ 3 ];  //DX
	vendor[ 12 ] = '\0';
}