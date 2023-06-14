# Detecting Threats With Microsoft Sentinel


## Introduction
In this lab we will:
- Configure and Deploy Azure Resources such as Log Analytics Workspace, Virtual Machines, and Azure Sentinel
- Implement Network and Virtual Machine Security Best Practices
- Utilize Data Connectors to bring data into Sentinel for Analysis
- Understand Windows Security Event logs
- Configure Windows Security Policies
- Utilize KQL to query Logs
- Write Custom Analytic Rules to detect Microsoft Security Events
- Utilize MITRE ATT&CK to map adversary tactics, techniques, detection and mitigation procedures

#
<details>
<summary>
  
### Step 1: Deploying a VM and enabling JIT access

</summary>  
<br/>
 In this lab, we will first create the virtual machine (VM) inside a resource group. A resource group is simply a way to logical separate our cloud resources in Azure.
 One way to create a resource group is to search for 'Resource Group' in the portal searchbar, and then clicking 'Create'. We can then fill in the name and select the region desired for our resource group.
 Now, from the main page of the Azure portal, click 'Create a Resouce', then click create under 'Virtual Machine'.
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/8797c346-db1a-476e-b726-a96799f5c902)
  
  We will configure the virtual machine as follows:
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/22db55dd-baff-43b7-9c12-7836d2114648)
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/afc0331a-1883-45c2-ae26-cc5d6c51e42b)

  Note that we have enabled 3389 as an inbound port. This will allow us to use Remote Desktop Protocol to access our VM. However, since we have enabled RDP on our VM, it may be subject to brute force attacks. To mitigate this threat, we will enable just-in-time (JIT) VM access. With JIT, we can limit access to our VM by time or even allow only our IP. More about JIT can be read <a href="https://docs.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage?tabs=jit-config-asc%2Cjit-request-asc">here</a>. To enable this, access Microsoft Defender for Cloud, which can be done by searching for this service via the search bar at the top of the portal. In the Environment Settings section of Microsoft Defender for Cloud, select ‘enable all plans’. This will give us access to the enhanced security features in our subscription which we will need to enable JIT. 
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/6275e42f-49d3-44e2-973c-49c4fbb017af)

  Now, go to the Workload Protections in Microsoft Defender for Cloud via the left panel. Under ‘Advanced Protection’, select Just-in-time VM access. 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/0be6faca-47e6-4df0-8015-09a1fab8489a)
Now, enable JIT on the VM being used for the project:
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/40ed7b58-84ce-46a9-997f-673d1a4fd83e)

  From here, we can navigate to the settings page for our VM, and in the 'Connect' pane select ‘My IP’ as the Source IP and Request access.
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/7889a02e-0f8e-4c2e-85b4-81eb0793d7f0)

  Now, the VM will only be allowed RDP access from the IP we are using. 

  </details>
  
  
  #
<details>
<summary>
  
### Step 2: Create a Log Analytics Workspace and Deploy Microsoft Sentinel 
</summary>  
<br/>
Now, we will create a Log Analytics Workspace and deploy Microsoft Sentinel. The Log Analytics workspace will collect and store the log data.

Search for Microsoft Sentinel in the Azure portal  search bar and click Create to create a Log Analytics workspace. 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/0de1add1-61b3-4516-94fe-221d962e1642)

As always, ensure the workspace is being applied to the correct Resource group. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/449351fb-1a17-4857-9c03-a551b8b557cc)

  Now, go to Microsoft Sentinel via the search bar, and add Sentinel to the workspace. 
  
  Initially, there will be nothing to display until we click the button which will prompt us to add Sentinel to the workspace:
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/379f8c52-6d9e-4b61-aede-c98a2ff3db99)

  Select the workspace we created and click 'Add'. 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/47f90eaf-affe-4672-9bd4-a70609de4ae6)

  Now, we are able to access the logs workspace after navigating to Microsoft Sentinel. 
  </details>
  

  #
<details>
<summary>
  
### Step 3: Getting Data into Microsoft Sentinel  
</summary>  
<br/>
Now, we need to utilize a data connector to create a data collection rule to import data from the Windows VM so we can view detected incidents[b]. Under the ‘Data connectors’ tab under ‘Configuration’ in Sentinel, search for ‘Windows Security Events’ and select ‘Windows Security Events via AMA’ and click on  ‘Open Connector Page’.   
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/a2daca98-c28b-43db-9d24-3a41cc8b2ab2)

  
  From here, we can now click 'Create data collection rule'.

  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/88328751-2980-464c-ab56-5bf7674ac3c1)

  Select the Windows VM resource that has been created, and create the rule. For this project we will stream ‘All Security Events’ as shown:
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/9e353f92-a7a5-4674-83c0-cac4d6ca9f33)
  
  Finally, click 'Create'. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/b579d61f-a761-4cf9-8b5f-6decf9b7ab5c)
  
  Now, if we go back to the 'Data connectors' panel in Sentinel we can see that ‘Windows Security Events via AMA’ is now connected. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/c03a2cc5-f0d2-46f1-bb16-750ccc669a46)

</details>



  #
<details>
<summary>
  
### Step 4: Generating Security Events  
</summary>  
<br/>
Since our VM is now connected to Sentinel and the Log Analytics workspace, we can now take actions within our Windows 10 VM that will create security alerts.
 Navigate to the VM in the Azure portal and ensure that the VM is running
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/8210e704-faee-47c1-8dda-111ddcaf580b)

  
  We will now RDP into our VM. From a local Windows machine, the 'Remote Desktop Connection' program may be used to achieve this. Enter the public IP of the VM which can be found in the 'Networking' section of the VM's page. 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/ccf1d077-64e3-43cc-95d6-b69857941d16)

  Inside the VM, access the 'Event Viewer' application which can be done by searching for it from the start menu. Navigate to Security which is under 'Windows Logs'. One event we can view is Event 4624 which corresponds to a successful login. We can use the find tool to highlight instances of this. Clicking the event will bring up more detailed information about the action. 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/8076f53a-ff85-4f55-801a-defb9a2b7f85)

 </details>
  
  
  #
<details>
<summary>
  
### Step 5: Using KQL to extract data  
</summary>  
<br/>
We can now use the Microsoft Sentinel SIEM to view security logs pertaining to our VM. In the ‘Logs’ section of the Log Analytics workspace created in Microsoft Sentinel, we can use Kusto Query Language, KQL, to extract the desired data.
  For instance, we can use the following query to show instances of successful logins:
  
  ```
  SecurityEvent
| where EventID == 4624
| project TimeGenerated, Computer, AccountName
 ```
   
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/8b5fd209-2069-473a-b194-8e5f3ebd79a0)

  This shows the event from the Security Event table, showing the event with ID 4624, and shows the time the event was generated, the computer name.
Another event we can view is an unsuccessful login, which would have an EventID of 4625. To generate such an alert, we may attempt to RDP into the machine but provide an incorrect password on purpose. 
 </details>
 
   #
<details>
<summary>
  
### Step 6: Creating Analytic Rule with KQL & Generating Scheduled Tasks   
</summary>  
<br/>
Now, we can create analytic rules to be alerted about certain events. Upon the detection of a specified activity in our VM, an alert will be generated. In the analytics section of Microsoft Sentinel, there are various rule templates that may be used to automatically generate alerts. These are alerts built into the SIEM that we can start using to monitor our infrastructure. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/be25c668-5029-4c34-b4f9-61be1aff7a83)

  <strong> Scheduled Task and Persistence Techniques: </strong>
 
  In this lab, we will used the scheduled task/job technique to simulate tactics done by adversaries. While some scheduled tasks can be harmless, such as starting a non-malicious program, threat actors often use this functionality to establish persistence. The MITRE attack framework discusses this technique in detail <a href="https://attack.mitre.org/techniques/T1053/">here</a>.
  
As stated, “Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time… Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence.” While the scheduled task we will create is harmless, such actions may be associated with malicious intent by threat actors." 
 
  In this lab, our scheduled task will not be malicious as we will be creating a scheduled task that opens a browser at a specific time. However, we will create an analytic rule that will monitor for this type of event so that we will be alerted in the SIEM about this kind of action.

  Since it is not enabled by default, we need to enable logging for a scheduled task creation. In our VM, we can open the ‘Local Security Policy’ application. Under ‘Advanced Audit Policy Configuration’ and ‘System Audit Policies’, we can select 'Object Access’. From here, select ‘Audit Other Object Access Events’ and enable both ‘success’ and ‘failure’ as shown. After completing this step, logging will be enabled for scheduled task events. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/9b31418d-c038-476f-9ba1-648d6b4257d5)

  <strong> Creating the Scheduled Task: </strong>
  
  Finally, scheduling a task in Windows 10 can be done by opening the ‘Task Scheduler’ application and using the ‘Create Task’ feature. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/a1c99243-b94b-4a65-83ff-f14100fbd5d1)

  Under Triggers, set a time in the future. Under actions, we can set an action to start a program. In this example, I have chosen to start Microsoft Edge.
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/5da52314-da5d-4fe6-8e4f-4bea9234de98)

  The scheduled task creation will now also show up in the Security section of 'Event Viewer' in the VM with an Event ID of 4698. Now, we can create the analytic rule to alert us about this in our SIEM.
  
  <strong> Writing the analytic rule using KQL: </strong>
  In this step, we will use a KQL query to alert us when a scheduled task is created.
Note that when we run the query in the Logs section of the workspace, specific events can be expanded to show the ‘EventData’.  
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/6ba76b10-d4b9-4732-a8d4-e5dda6a80be0)
In the ‘EventData’ section, we can find more useful information, such as the scheduled tasks name, the ClientProcessID, the username of the account that the task was created on, and more. We can use the 'parse' command in our KQL query to extract data from the 'EventData' Field that we find important, and use the 'project' command to display the data fields as columns:
  ```
  SecurityEvent                            
 | where EventID == 4698
 | parse EventData with * '<Data Name="SubjectUserName">' User '</Data>' *
 | parse EventData with * '<Data Name="TaskName">' NameofScheuduledTask '</Data>' *
 | parse EventData with * '<Data Name="ClientProcessId">' ClientProcessID '</Data>' *
 | project Computer, TimeGenerated, ClientProcessID, NameofScheuduledTask, User
  ```
  Under Results, this will now show us the Computer, Time Generated, the ClientProcessID, the name of the task that was scheduled, and the User. Thus, we can generate Event Data and place it into its own category for readability. This may be beneficial for the analyst investigating the logs. 
  
  We will now use this KQL logic to alert us when new scheduled tasks are created. Navigate back to Microsoft Sentinel, open the analytics workspace previously created. Open  ‘Analytics’ and click ‘Create’ to find the option to create a ‘Scheduled query rule’.
  We will create a new scheduled rule as follows:
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/57062fc5-0670-4d8b-a8e0-bfc7382a5e1a)
  
  For the rule logic, use the KQL query that was created to extract our desired information: 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/973f06c3-da99-41c0-861e-4b18498354cc)
  
  We will also utilize Alert Enrichment. The purpose of this is to provide more relevant context to our alerts.
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/ea293791-b835-4019-8417-1eb285a813bc)

  Under query scheduling, set the query to run every 5 minutes. It is 5 hours by default:
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/93fec7d2-8810-45e0-9930-f303e507e641)

  The full configuration for the scheduled rule is as follows: 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/bbf83ef8-8a7b-409a-9726-3345f3166e02)

  
  After creating this rule, we can create another task in the Windows VM as before, and the alert will be triggered in Microsoft Sentinel. Once more tasks are created, we can view the occurrences in the ‘Incidents’ page of Microsoft Sentinel.
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/639c4d72-4042-403e-8489-5c135c4a1a24)

  Since we utilized entity mapping when creating the scheduled rule, we can also see the information such as the user, machine name, task name, and the process ID which would help in an investigative process. The security analyst could now use this information along with other tools to evaluate the alert. 
  
 </details>
  
  

   #
<details>
<summary>
  
### Step 7: Creating Analytic Rule with KQL & Generating Scheduled Tasks   
</summary>  
<br/>
Now, we can create analytic rules to be alerted about certain events. Upon the detection of a specified activity in our VM, an alert will be generated. In the analytics section of Microsoft Sentinel, there are various rule templates that may be used to automatically generate alerts. These are alerts built into the SIEM that we can start using to monitor our infrastructure. 
  
![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/be25c668-5029-4c34-b4f9-61be1aff7a83)

  <strong> Scheduled Task and Persistence Techniques: </strong>
 
  In this lab, we will used the scheduled task/job technique to simulate tactics done by adversaries. While some scheduled tasks can be harmless, such as starting a non-malicious program, threat actors often use this functionality to establish persistence. The MITRE attack framework discusses this technique in detail <a href="https://attack.mitre.org/techniques/T1053/">here</a>.
  
As stated, “Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time… Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence.” While the scheduled task we will create is harmless, such actions may be associated with malicious intent by threat actors." 
 
  In this lab, our scheduled task will not be malicious as we will be creating a scheduled task that opens a browser at a specific time. However, we will create an analytic rule that will monitor for this type of event so that we will be alerted in the SIEM about this kind of action.

  Since it is not enabled by default, we need to enable logging for a scheduled task creation. In our VM, we can open the ‘Local Security Policy’ application. Under ‘Advanced Audit Policy Configuration’ and ‘System Audit Policies’, we can select 'Object Access’. From here, select ‘Audit Other Object Access Events’ and enable both ‘success’ and ‘failure’ as shown. After completing this step, logging will be enabled for scheduled task events. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/9b31418d-c038-476f-9ba1-648d6b4257d5)

  <strong> Creating the Scheduled Task: </strong>
  
  Finally, scheduling a task in Windows 10 can be done by opening the ‘Task Scheduler’ application and using the ‘Create Task’ feature. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/a1c99243-b94b-4a65-83ff-f14100fbd5d1)

  Under Triggers, set a time in the future. Under actions, we can set an action to start a program. In this example, I have chosen to start Microsoft Edge.
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/5da52314-da5d-4fe6-8e4f-4bea9234de98)

  The scheduled task creation will now also show up in the Security section of 'Event Viewer' in the VM with an Event ID of 4698. Now, we can create the analytic rule to alert us about this in our SIEM.
  
  <strong> Writing the analytic rule using KQL: </strong>
  In this step, we will use a KQL query to alert us when a scheduled task is created.
Note that when we run the query in the Logs section of the workspace, specific events can be expanded to show the ‘EventData’.  
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/6ba76b10-d4b9-4732-a8d4-e5dda6a80be0)
In the ‘EventData’ section, we can find more useful information, such as the scheduled tasks name, the ClientProcessID, the username of the account that the task was created on, and more. We can use the 'parse' command in our KQL query to extract data from the 'EventData' Field that we find important, and use the 'project' command to display the data fields as columns:
  ```
  SecurityEvent                            
 | where EventID == 4698
 | parse EventData with * '<Data Name="SubjectUserName">' User '</Data>' *
 | parse EventData with * '<Data Name="TaskName">' NameofScheuduledTask '</Data>' *
 | parse EventData with * '<Data Name="ClientProcessId">' ClientProcessID '</Data>' *
 | project Computer, TimeGenerated, ClientProcessID, NameofScheuduledTask, User
  ```
  Under Results, this will now show us the Computer, Time Generated, the ClientProcessID, the name of the task that was scheduled, and the User. Thus, we can generate Event Data and place it into its own category for readability. This may be beneficial for the analyst investigating the logs. 
  
  We will now use this KQL logic to alert us when new scheduled tasks are created. Navigate back to Microsoft Sentinel, open the analytics workspace previously created. Open  ‘Analytics’ and click ‘Create’ to find the option to create a ‘Scheduled query rule’.
  We will create a new scheduled rule as follows:
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/57062fc5-0670-4d8b-a8e0-bfc7382a5e1a)
  
  For the rule logic, use the KQL query that was created to extract our desired information: 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/973f06c3-da99-41c0-861e-4b18498354cc)
  
  We will also utilize Alert Enrichment. The purpose of this is to provide more relevant context to our alerts.
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/ea293791-b835-4019-8417-1eb285a813bc)

  Under query scheduling, set the query to run every 5 minutes. It is 5 hours by default:
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/93fec7d2-8810-45e0-9930-f303e507e641)

  The full configuration for the scheduled rule is as follows: 
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/bbf83ef8-8a7b-409a-9726-3345f3166e02)

  
  After creating this rule, we can create another task in the Windows VM as before, and the alert will be triggered in Microsoft Sentinel. Once more tasks are created, we can view the occurrences in the ‘Incidents’ page of Microsoft Sentinel.
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/639c4d72-4042-403e-8489-5c135c4a1a24)

  Since we utilized entity mapping when creating the scheduled rule, we can also see the information such as the user, machine name, task name, and the process ID which would help in an investigative process. The security analyst could now use this information along with other tools to evaluate the alert. 
  
 </details>
  
  
  
  
   #
<details>
<summary>
  
### Step 8: Using the MITRE ATT&CK Framework   
</summary>  
<br/>
The observed MITRE ATT&CK tactic that we have detected using the Microsoft Sentinel SIEM in this lab is <a href="https://attack.mitre.org/tactics/TA0003/">TA0003 Persistence</a>. This tactic is used by threat actors to maintain access to systems despite system restarts, changed credentials, or other events that could remove their access from systems. We can use the MITRE ATT&CK Framework to narrow down the specific technique a potential threat actor may be using in this lab, and we can identify the technique and sub-technique as <a href="https://attack.mitre.org/techniques/T1053/005/">T1053.005</a>.
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/084dca44-75e5-4fb9-a5dd-9f43521516cf)

  
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/02b6f724-28f8-4543-b73e-5f09565579c6)

  
  <strong> Detection </strong>
  By logging specific Windows Event IDs with the help of Microsoft Sentinel, we were able to detect this activity. The MITRE ATT&CK Framework also outlines some recommendations by Microsoft for detection. 
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/d06f489b-faf4-4488-82ed-6fe67ca7bc36)

  
  <strong> Mitigation </strong> 
  One mitigation technique outlined in the MITRE ATT&CK Framework is <a href="https://attack.mitre.org/mitigations/M1018/">User Account Management, ID: M1018</a>.
  As shown, this technique can be mitigated by only authorizing administrators to create tasks on remote systems.
  
  ![image](https://github.com/romhaki/Detecting-Threats-With-Microsoft-Sentinel/assets/136436650/b29d8806-78e6-481e-84a1-f924731c0ba7)

  

  
 </details>
  
  
  

  
  
