//QList<QNetworkInterface> ls=QNetworkInterface::allInterfaces();
//prop[i]-mask (QString) 

#ifdef Q_OS_WIN

                    HRESULT hres;

                    // Step 1: --------------------------------------------------
                    // Initialize COM. ------------------------------------------

                    CoUninitialize();
                    //OleInitialize(NULL);
                    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
                   /* QString error;
                    error.setNum(hres,16);*/
                    if (FAILED(hres))
                    {
                        return answer=("Failed to initialize COM library. Error code = 0x"+QString::number(hres));
                    }

                    // Step 2: --------------------------------------------------
                    // Set general COM security levels --------------------------

                    hres = CoInitializeSecurity(
                        NULL,
                        -1,                          // COM negotiates service
                        NULL,                        // Authentication services
                        NULL,                        // Reserved
                        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
                        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
                        NULL,                        // Authentication info
                        EOAC_NONE,                   // Additional capabilities
                        NULL                         // Reserved
                    );


                    if (FAILED(hres))
                    {
                        CoUninitialize();
                        return answer=("Failed to initialize security. Error code = 0x"+hres);
                    }

                    // Step 3: ---------------------------------------------------
                    // Obtain the initial locator to WMI -------------------------

                    IWbemLocator *pLoc = NULL;

                    hres = CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,IID_IWbemLocator, (LPVOID *)&pLoc);

                    if (FAILED(hres))
                    {
                        CoUninitialize();
                        return answer=("Failed to create IWbemLocator object. Err code = 0x"+hres);
                    }

                    // Step 4: ---------------------------------------------------
                    // Connect to WMI through the IWbemLocator::ConnectServer method

                    IWbemServices *pSvc = NULL;

                    // Connect to the local root\cimv2 namespace
                    // and obtain pointer pSvc to make IWbemServices calls.
                    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),NULL,NULL,0,NULL,0,0,&pSvc);

                    if (FAILED(hres))
                    {
                        pLoc->Release();
                        CoUninitialize();
                        return answer=("Could not connect. Error code = 0x"+hres);
                    }

                    //answer=("Connected to ROOT\\CIMV2 WMI namespace");


                    // Step 5: --------------------------------------------------
                    // Set security levels for the proxy ------------------------

                    hres = CoSetProxyBlanket(
                        pSvc,                        // Indicates the proxy to set
                        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
                        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
                        NULL,                        // Server principal name
                        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
                        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
                        NULL,                        // client identity
                        EOAC_NONE                    // proxy capabilities
                    );

                    if (FAILED(hres))
                    {
                        pSvc->Release();
                        pLoc->Release();
                        CoUninitialize();
                        return answer=("Could not set proxy blanket. Error code = 0x"+hres);
                    }

                    // Step 6: --------------------------------------------------
                    // Use the IWbemServices pointer to make requests of WMI ----

                    // set up to call the Win32_Process::Create method
                    BSTR MethodName = SysAllocString(L"EnableStatic");
                    BSTR ClassName = SysAllocString(L"Win32_NetworkAdapterConfiguration");

                    IWbemClassObject* pClass = NULL;
                    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

                    if (FAILED(hres))
                    {
                        return answer=("pSvc->GetObject. Error code = 0x"+hres);
                    }

                    IWbemClassObject* pInParamsDefinition = NULL;
                    hres = pClass->GetMethod(MethodName, 0, &pInParamsDefinition, NULL);

                    if (FAILED(hres))
                    {
                        return answer=("GetMethod. Error code = 0x"+hres);
                    }

                    IWbemClassObject* pClassInstance = NULL;
                    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

                    if (FAILED(hres))
                    {
                        return answer=("SpawnInstance. Error code = 0x"+hres);
                    }


                    ULONG count = 1;		//  ip\mask list lenght
                    size_t outSize;


                    int fIndex=0;			// interface index

                    LPWSTR adapterName=QStringToLPWSTR(ls[id].humanReadableName());
                    GetAdapterIndex(adapterName,(PULONG)fIndex);

                    std::wstring ipWstr=ls[id].addressEntries().first().ip().toString().toStdWString();
                    wchar_t* tmp_ip=const_cast<wchar_t*>(ipWstr.c_str());

                    std::wstring maskWstr=prop[i].section(':', 1).toStdWString();
                    wchar_t* tmp_mask=const_cast<wchar_t*>(maskWstr.c_str());


                    // Convert from multibyte strings to wide character arrays
                    //wchar_t tmp_ip[_countof(iptemp)];
                        SAFEARRAY *ip_list = SafeArrayCreateVector(VT_BSTR, 0, count);
                    // Insert into safe arrays, allocating memory as we do so (destroying the safe array will destroy the allocated memory)
                        long idx[] = { 0 };
                        BSTR ipT = SysAllocString(tmp_ip);
                        idx[0] = 0;
                        if (FAILED(SafeArrayPutElement(ip_list, idx, ipT)))
                        {
                           return answer=( "SafeArrayPutElement ip= 0x"+hres);
                        }
                        SysFreeString(ipT);


                        SAFEARRAY *mask_list = SafeArrayCreateVector(VT_BSTR, 0, count);
                        // Insert into safe arrays, allocating memory as we do so (destroying the safe array will destroy the allocated memory)
                        BSTR maskT = SysAllocString(tmp_mask);
                        idx[0] = 0;
                        if (FAILED(SafeArrayPutElement(mask_list, idx, maskT)))
                        {
                            return answer=("SafeArrayPutElement mask= 0x"+hres);
                        }
                        SysFreeString(maskT);


                        // Create the values for the in parameters
                        VARIANT ip;
                        VariantInit(&ip);
                        ip.vt = VT_ARRAY | VT_BSTR;
                        ip.parray = ip_list;

                        VARIANT mask;
                        VariantInit(&mask);
                        mask.vt = VT_ARRAY | VT_BSTR;
                        mask.parray = mask_list;

                        // Store the value for the in parameters
                        hres = pClassInstance->Put(L"IPAddress", 0, &ip, 0);

                    if (FAILED(hres))
                    {
                       return answer=("put ip. Error code = 0x"+hres);
                    }

                    hres = pClassInstance->Put(L"SubNetMask", 0, &mask, 0);

                    if (FAILED(hres))
                    {
                        return answer=("put mask. Error code = 0x"+hres);
                    }



                    char indexString[10];
                    _itoa_s(fIndex, indexString, 10,10);

                    char instanceString[100];
                    wchar_t w_instanceString[100];
                    strcpy_s(instanceString, "Win32_NetworkAdapterConfiguration.Index='");
                    strcat_s(instanceString, indexString);
                    strcat_s(instanceString, "'");

                    size_t size = 100;
                    mbstowcs_s(&outSize, w_instanceString, size, instanceString, size - 1);

                    BSTR InstancePath = SysAllocString(w_instanceString);



                    // Execute Method
                    IWbemClassObject* pOutParams = NULL;
                    hres = pSvc->ExecMethod(InstancePath, MethodName, 0,NULL, pClassInstance, &pOutParams, NULL);

                    if (FAILED(hres))
                    {
                        VariantClear(&ip);
                        VariantClear(&mask);
                        SysFreeString(ClassName);
                        SysFreeString(MethodName);
                        pClass->Release();
                        pClassInstance->Release();
                        pInParamsDefinition->Release();
                        pOutParams->Release();
                        pSvc->Release();
                        pLoc->Release();
                        CoUninitialize();
                        return answer=("Could not execute method. Error code = 0x"+hres);
                    }

                    // To see what the method returned,
                    // use the following code.  The return value will
                    // be in &varReturnValue
                    VARIANT varReturnValue;
                    hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);

                    // Clean up
                    //--------------------------
                    VariantClear(&ip);
                    VariantClear(&mask);
                    VariantClear(&varReturnValue);
                    SysFreeString(ClassName);
                    SysFreeString(MethodName);
                    pClass->Release();
                    pClassInstance->Release();
                    pInParamsDefinition->Release();
                    pOutParams->Release();
                    pLoc->Release();
                    pSvc->Release();
                    CoUninitialize();
                    answer=("Ok");

                #else

                    const char* _INTERFACE_NAME = ls[id].humanReadableName().toStdString().data() ;
                    const char* _SUBNET_MASK=prop[i].section(':', 1).toStdString().data();

                    bool is_error=false;


                    int sockfd,  ioctl_result;
                    int subnet_mask_config_result;
                    struct ifreq ifr;
                    /// note: no pointer here
                    struct sockaddr_in subnet_mask;

                    // Prepare the struct ifreq

                    bzero(ifr.ifr_name, IFNAMSIZ);
                    strcpy(ifr.ifr_name, _INTERFACE_NAME);

                    /// note: prepare the two struct sockaddr_in

                    subnet_mask.sin_family = AF_INET;
                    subnet_mask_config_result = inet_pton(AF_INET, _SUBNET_MASK, &(subnet_mask.sin_addr));

                    // Error handling


                    if((subnet_mask_config_result == 0)&!is_error)
                    {
                        is_error=true;
                         answer="%s: inet_pton: Invalid IPv4 subnet mask.\n"+QString(_INTERFACE_NAME)+"\n "+strerror(errno);
                       // QMessageBox::information(0,"Error", "%s: inet_pton: Invalid IPv4 subnet mask.\n"+QString(_INTERFACE_NAME)+"\n "+strerror(errno));
                    }

                    if((subnet_mask_config_result < 0)&!is_error)
                    {
                        is_error=true;
                        answer="inet_pton: "+QString(_INTERFACE_NAME)+"\n "+strerror(errno);
                       // QMessageBox::information(0,"Error", "inet_pton: "+QString(_INTERFACE_NAME)+"\n "+strerror(errno));
                    }
                    // Open socket for ioctl calls

                    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                    if((sockfd < 0)&!is_error)
                    {
                        is_error=true;
                         answer="socket: "+QString(_INTERFACE_NAME)+" "+strerror(errno);
                        //QMessageBox::information(0,"Error", "socket: "+QString(_INTERFACE_NAME)+"\n "+strerror(errno));
                    }

                    // Call ioctl to configure network devices

                    /// put mask in ifr structure
                    memcpy(&(ifr.ifr_addr), &subnet_mask, sizeof (struct sockaddr));
                    ioctl_result = ioctl(sockfd, SIOCSIFNETMASK, &ifr);   // Set subnet mask
                    if((ioctl_result < 0)&!is_error)
                    {
                        is_error=true;
                         answer="ioctl SIOCSIFNETMASK: "+QString(_INTERFACE_NAME)+"\n "+strerror(errno);
                        //QMessageBox::information(0,"Error", "ioctl SIOCSIFNETMASK: "+QString(_INTERFACE_NAME)+"\n "+strerror(errno));
                    }

                      ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

                      ioctl_result =ioctl(sockfd, SIOCSIFFLAGS, &ifr);
                      if((ioctl_result < 0)&!is_error)
                      {
                          is_error=true;
                           answer="ioctl SIOCGIFFLAGS: "+QString(_INTERFACE_NAME)+"  "+strerror(errno);
                          //QMessageBox::information(0,"Error", "ioctl SIOCSIFFLAGS: "+QString(_INTERFACE_NAME)+"\n "+strerror(errno));
                      }


                      if (!is_error)
                           answer="Ok";
                          //QMessageBox::information(0,"Info","Network device configured\n");

                #endif
