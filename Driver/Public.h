/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_Driver,
    0x03f8f3ef,0xfda3,0x4527,0xb5,0x0c,0x87,0x57,0x5e,0xf7,0xfe,0xb6);
// {03f8f3ef-fda3-4527-b50c-87575ef7feb6}
