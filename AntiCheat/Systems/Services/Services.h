#pragma once
#include "../Utils/singleton.h"
#include <string>
#include <vector>

struct Service
{
	std::string displayName;
	std::string serviceName;
	DWORD pid;
	bool isRunning;
};

struct Device
{
	std::string InstanceID;
	std::string Description;
};

struct DeviceW
{
	std::string InstanceID;
	std::string Description;
};

enum WindowsVersion
{									//Major,Minor :
	Windows2000 = 50 ,				//5,0
	WindowsXP = 51 ,			    //5,1
	WindowsXPProfessionalx64 = 52 ,	//5,2
	WindowsVista = 60 ,				//6,0
	Windows7 = 61 ,					//6,1
	Windows8 = 62 ,					//6,2
	Windows8_1 = 63 ,				//6,3
	Windows10 = 10 ,					//10
	Windows11 = 11 ,					//10  -> build number changes 

	ErrorUnknown = 0
};

/*
The Services class deals with keeping track of loaded drivers & services/recurring tasks on the system, along with misc windows functions
*/
class Services : public CSingleton<Services>
{
public:



	Services operator+( Services & other ) = delete; //delete all arithmetic operators, unnecessary for context
	Services operator-( Services & other ) = delete;
	Services operator*( Services & other ) = delete;
	Services operator/( Services & other ) = delete;

	bool GetLoadedDrivers( std::vector<std::string> * buffer ); //adds to `DriverPaths`
	bool GetServiceModules( ); //adds to `ServiceList`

	std::vector< std::string> GetUnsignedDrivers( );

	bool IsTestsigningEnabled( );
	bool IsDebugModeEnabled( );

	bool IsSecureBootEnabled( );
	bool IsSecureBootEnabled_RegKey( ); //check by reg key

	std::string GetWindowsDrive( );
	std::string GetWindowsDriveW( );

	bool IsRunningAsAdmin( );

	std::vector<DeviceW> GetHardwareDevicesW( );
	bool CheckUSBDevices( );

	WindowsVersion GetWindowsVersion( );

	bool IsHypervisor( );
	void GetHypervisorVendor( __out char vendor[ 13 ] );

private:

	std::vector<Service *> ServiceList;
	std::vector <std::string> DriverPaths;
};