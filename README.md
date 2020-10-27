Azure: Use Azure File Service
=============================

            


What are Azure files?

The Azure File service exposes file shares using the standard SMB 2.1 protocol. Applications running in Azure can now easily share files between VMs using standard and familiar file system APIs like ReadFile and WriteFile. Azure
 Files is built on the same technology as the Blob, Table, and Queue Services, which means Azure Files is able to leverage the existing availability, durability, scalability, and geo redundancy that is built into our platform.



http://blogs.msdn.com/b/windowsazurestorage/archive/2014/05/12/introducing-microsoft-azure-file-service.aspx


This PowerShell script allows has the following features:


  *  Create Azure Storage Account

  *  Create a Share 
  *  Remove a Share 
  *  Print NET USE command for Windows IaaS VM

  *  Print Sudo Mount command for Linux IaaS VM

  *  Create a directory in Azure Files Share

  *  Create one gigabyte test file

  *  Upload a local file to Azure Files

  *  Download a file from Azure Storage


 

 

 


 






















 

 

        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
